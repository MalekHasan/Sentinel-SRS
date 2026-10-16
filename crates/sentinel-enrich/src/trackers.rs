// SPDX-License-Identifier: GPL-3.0-or-later
//! Tracker domains: which company a destination belongs to and what kind of tracking it
//! does, from published tracker lists (SRS DT-06; ADR-0010). A listed domain covers the
//! names below it: the company comes from the nearest listed domain that names one, and
//! the categories likewise, each with the lists that say so.
//!
//! Layout, all integers little-endian:
//!
//! ```text
//! magic "SNTLTRKR", version u32
//! sources:    count u32, texts         (at most 8)
//! companies:  count u32, texts
//! categories: count u32, texts         (at most 64)
//! domains:    count u32, then per domain, sorted by its bytes:
//!             text, company u32 (u32::MAX: none), categories u64 (bit set),
//!             company sources u8, category sources u8 (bit sets)
//! ```
//!
//! A domain has a company and the sources that name it, or neither; the same holds for
//! its categories; and it has at least one of the two.
//!
//! A text is a length (u32) and UTF-8 bytes. Domains are lower-case ASCII.

use std::collections::{BTreeMap, HashMap};

const MAGIC: &[u8; 8] = b"SNTLTRKR";
const VERSION: u32 = 1;
const MAX_SOURCES: usize = 8;
const MAX_CATEGORIES: usize = 64;
const MAX_DOMAINS: usize = 4 * 1024 * 1024;
const MAX_TEXT: usize = 1024;
const NO_COMPANY: u32 = u32::MAX;

/// What the tracker lists say about a destination: its company, its categories (for
/// example "Advertising" or "Analytics"), or both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackerInfo<'a> {
    pub company: Option<Listed<'a, &'a str>>,
    pub categories: Option<Listed<'a, Vec<&'a str>>>,
}

/// One answer from the tracker lists, and why we believe it (DT-02).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed<'a, T> {
    pub value: T,
    /// The listed domain it comes from: the hostname itself or a domain above it.
    pub domain: &'a str,
    /// The lists that say so, for example "DuckDuckGo Tracker Radar 2026-10-15".
    pub sources: Vec<&'a str>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TrackerLoadError {
    #[error("not a Sentinel tracker list")]
    NotATrackerList,
    #[error("tracker list version {0} is not supported")]
    UnsupportedVersion(u32),
    #[error("the tracker list is cut short")]
    Truncated,
    #[error("the tracker list has a table or text larger than allowed")]
    TooLarge,
    #[error("the tracker list has domains out of order")]
    NotSorted,
    #[error("the tracker list has an invalid domain")]
    BadDomain,
    #[error("the tracker list refers to a company, category or source it does not have")]
    BadReference,
    #[error("the tracker list has text that is not valid UTF-8, or has control characters")]
    BadText,
    #[error("the tracker list has data after its end")]
    TrailingBytes,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TrackerBuildError {
    #[error("{0:?} is not a domain name")]
    BadDomain(String),
    #[error("more than {MAX_SOURCES} sources")]
    TooManySources,
    #[error("more than {MAX_CATEGORIES} categories")]
    TooManyCategories,
    #[error("more than {MAX_DOMAINS} domains")]
    TooManyDomains,
    #[error("text longer than {MAX_TEXT} bytes: {0:?}")]
    TextTooLong(String),
    #[error("text with a control or text direction character: {0:?}")]
    ControlCharacter(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    company: u32,
    categories: u64,
    company_sources: u8,
    category_sources: u8,
}

/// A loaded tracker list.
#[derive(Debug)]
pub struct TrackerDb {
    sources: Vec<String>,
    companies: Vec<String>,
    categories: Vec<String>,
    /// Sorted by domain.
    domains: Vec<(String, Entry)>,
}

impl TrackerDb {
    /// Check and load a tracker list file's contents.
    pub fn from_bytes(bytes: &[u8]) -> Result<TrackerDb, TrackerLoadError> {
        let mut r = Reader { bytes, pos: 0 };
        if r.take(MAGIC.len())
            .map_err(|_| TrackerLoadError::NotATrackerList)?
            != MAGIC
        {
            return Err(TrackerLoadError::NotATrackerList);
        }
        let version = r.u32()?;
        if version != VERSION {
            return Err(TrackerLoadError::UnsupportedVersion(version));
        }
        let sources = r.texts(MAX_SOURCES)?;
        let companies = r.texts(MAX_DOMAINS)?;
        let categories = r.texts(MAX_CATEGORIES)?;
        let count = r.count(MAX_DOMAINS, 4 + 4 + 8 + 1 + 1)?;
        let mut domains: Vec<(String, Entry)> = Vec::with_capacity(count);
        for _ in 0..count {
            let domain = r.text()?;
            if !valid_domain(&domain) {
                return Err(TrackerLoadError::BadDomain);
            }
            if domains.last().is_some_and(|(last, _)| *last >= domain) {
                return Err(TrackerLoadError::NotSorted);
            }
            let entry = Entry {
                company: r.u32()?,
                categories: r.u64()?,
                company_sources: r.u8()?,
                category_sources: r.u8()?,
            };
            let known_company =
                entry.company == NO_COMPANY || (entry.company as usize) < companies.len();
            let known_categories =
                categories.len() == 64 || entry.categories >> categories.len() == 0;
            let known_sources =
                u32::from(entry.company_sources | entry.category_sources) >> sources.len() == 0;
            // Each answer with its sources, or neither; and at least one answer.
            let whole = (entry.company == NO_COMPANY) == (entry.company_sources == 0)
                && (entry.categories == 0) == (entry.category_sources == 0)
                && (entry.company_sources | entry.category_sources) != 0;
            if !(known_company && known_categories && known_sources && whole) {
                return Err(TrackerLoadError::BadReference);
            }
            domains.push((domain, entry));
        }
        if r.pos != bytes.len() {
            return Err(TrackerLoadError::TrailingBytes);
        }
        Ok(TrackerDb {
            sources,
            companies,
            categories,
            domains,
        })
    }

    /// What the lists say about `hostname`: the company and the categories of the
    /// hostname itself, or of the nearest domain above it that has them. `None` if no
    /// list covers it. Case and a final dot do not matter.
    pub fn lookup(&self, hostname: &str) -> Option<TrackerInfo<'_>> {
        let host = hostname.trim_end_matches('.').to_ascii_lowercase();
        // An address is not a name: "192.0.2.7" must not match a domain "2.7".
        if host.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }
        let mut info = TrackerInfo {
            company: None,
            categories: None,
        };
        let mut candidate = host.as_str();
        while info.company.is_none() || info.categories.is_none() {
            if let Ok(i) = self
                .domains
                .binary_search_by(|(domain, _)| domain.as_str().cmp(candidate))
            {
                let (domain, entry) = &self.domains[i];
                if info.company.is_none() && entry.company != NO_COMPANY {
                    info.company = Some(Listed {
                        value: self.companies[entry.company as usize].as_str(),
                        domain,
                        sources: names_in(u64::from(entry.company_sources), &self.sources),
                    });
                }
                if info.categories.is_none() && entry.categories != 0 {
                    info.categories = Some(Listed {
                        value: names_in(entry.categories, &self.categories),
                        domain,
                        sources: names_in(u64::from(entry.category_sources), &self.sources),
                    });
                }
            }
            match candidate.find('.') {
                Some(dot) => candidate = &candidate[dot + 1..],
                None => break,
            }
        }
        (info.company.is_some() || info.categories.is_some()).then_some(info)
    }

    /// Every list the file was built from.
    pub fn sources(&self) -> &[String] {
        &self.sources
    }

    pub fn len(&self) -> usize {
        self.domains.len()
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }
}

/// Identifies one list given to a [`TrackerDbBuilder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceId(u8);

/// Collects tracker domains from the source lists, then writes the file. A domain named
/// by several lists keeps the first company given, and all categories; the sources of
/// each are the lists that gave one.
#[derive(Debug, Default)]
pub struct TrackerDbBuilder {
    sources: Vec<String>,
    companies: Names,
    categories: Names,
    domains: BTreeMap<String, Entry>,
}

/// Names in the order first given, each with its number.
#[derive(Debug, Default)]
struct Names {
    list: Vec<String>,
    numbers: HashMap<String, u32>,
}

impl Names {
    /// The name's number, numbering it if it is new; `Err` if there are already `max`.
    fn number(&mut self, name: &str, max: usize) -> Result<u32, ()> {
        if let Some(&number) = self.numbers.get(name) {
            return Ok(number);
        }
        if self.list.len() == max {
            return Err(());
        }
        let number = self.list.len() as u32;
        self.list.push(name.to_owned());
        self.numbers.insert(name.to_owned(), number);
        Ok(number)
    }
}

impl TrackerDbBuilder {
    pub fn new() -> Self {
        TrackerDbBuilder::default()
    }

    /// A list the following domains come from, as the app names it, with its date.
    pub fn add_source(&mut self, label: &str) -> Result<SourceId, TrackerBuildError> {
        check_text(label)?;
        if self.sources.len() == MAX_SOURCES {
            return Err(TrackerBuildError::TooManySources);
        }
        self.sources.push(label.to_owned());
        Ok(SourceId((self.sources.len() - 1) as u8))
    }

    /// What `source` says about `domain`. Returns whether that was anything: a domain
    /// given without a company or a category is left out.
    pub fn add_domain(
        &mut self,
        source: SourceId,
        domain: &str,
        company: Option<&str>,
        categories: &[&str],
    ) -> Result<bool, TrackerBuildError> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if !valid_domain(&domain) {
            return Err(TrackerBuildError::BadDomain(domain));
        }
        if !self.domains.contains_key(&domain) && self.domains.len() == MAX_DOMAINS {
            return Err(TrackerBuildError::TooManyDomains);
        }
        let company = match company.map(str::trim).filter(|c| !c.is_empty()) {
            Some(name) => {
                check_text(name)?;
                // Never more companies than domains.
                self.companies
                    .number(name, MAX_DOMAINS)
                    .map_err(|()| TrackerBuildError::TooManyDomains)?
            }
            None => NO_COMPANY,
        };
        let mut category_bits = 0u64;
        for category in categories
            .iter()
            .map(|c| c.trim())
            .filter(|c| !c.is_empty())
        {
            check_text(category)?;
            let bit = self
                .categories
                .number(category, MAX_CATEGORIES)
                .map_err(|()| TrackerBuildError::TooManyCategories)?;
            category_bits |= 1 << bit;
        }
        if company == NO_COMPANY && category_bits == 0 {
            return Ok(false);
        }
        let entry = self.domains.entry(domain).or_insert(Entry {
            company: NO_COMPANY,
            categories: 0,
            company_sources: 0,
            category_sources: 0,
        });
        if company != NO_COMPANY {
            if entry.company == NO_COMPANY {
                entry.company = company;
            }
            entry.company_sources |= 1 << source.0;
        }
        if category_bits != 0 {
            entry.categories |= category_bits;
            entry.category_sources |= 1 << source.0;
        }
        Ok(true)
    }

    pub fn build(self) -> Result<Vec<u8>, TrackerBuildError> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        for list in [&self.sources, &self.companies.list, &self.categories.list] {
            out.extend_from_slice(&(list.len() as u32).to_le_bytes());
            for text in list {
                write_text(&mut out, text)?;
            }
        }
        out.extend_from_slice(&(self.domains.len() as u32).to_le_bytes());
        for (domain, entry) in &self.domains {
            write_text(&mut out, domain)?;
            out.extend_from_slice(&entry.company.to_le_bytes());
            out.extend_from_slice(&entry.categories.to_le_bytes());
            out.push(entry.company_sources);
            out.push(entry.category_sources);
        }
        Ok(out)
    }
}

/// The names whose bits are set.
fn names_in(set: u64, names: &[String]) -> Vec<&str> {
    names
        .iter()
        .enumerate()
        .filter(|(i, _)| set >> i & 1 == 1)
        .map(|(_, name)| name.as_str())
        .collect()
}

/// Lower-case ASCII letters, digits, '-' and '_' in dot-separated labels.
fn valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        })
}

/// Texts are shown as they are, one per line: no line breaks or other control
/// characters, and no marks that change the direction of the text around them.
fn forbidden_in_text(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{200e}' | '\u{200f}' | '\u{061c}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

fn check_text(text: &str) -> Result<(), TrackerBuildError> {
    if text.len() > MAX_TEXT {
        return Err(TrackerBuildError::TextTooLong(text.to_owned()));
    }
    if text.chars().any(forbidden_in_text) {
        return Err(TrackerBuildError::ControlCharacter(text.to_owned()));
    }
    Ok(())
}

fn write_text(out: &mut Vec<u8>, text: &str) -> Result<(), TrackerBuildError> {
    check_text(text)?;
    out.extend_from_slice(&(text.len() as u32).to_le_bytes());
    out.extend_from_slice(text.as_bytes());
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TrackerLoadError> {
        let end = self.pos.checked_add(n).ok_or(TrackerLoadError::Truncated)?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(TrackerLoadError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, TrackerLoadError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, TrackerLoadError> {
        let mut word = [0u8; 4];
        word.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(word))
    }

    fn u64(&mut self) -> Result<u64, TrackerLoadError> {
        let mut word = [0u8; 8];
        word.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(word))
    }

    /// A count of at most `max` entries of at least `min_size` bytes each.
    fn count(&mut self, max: usize, min_size: usize) -> Result<usize, TrackerLoadError> {
        let count = self.u32()? as usize;
        if count > max {
            return Err(TrackerLoadError::TooLarge);
        }
        if count.saturating_mul(min_size) > self.bytes.len() - self.pos {
            return Err(TrackerLoadError::Truncated);
        }
        Ok(count)
    }

    fn text(&mut self) -> Result<String, TrackerLoadError> {
        let len = self.u32()? as usize;
        if len > MAX_TEXT {
            return Err(TrackerLoadError::TooLarge);
        }
        let text =
            String::from_utf8(self.take(len)?.to_vec()).map_err(|_| TrackerLoadError::BadText)?;
        if text.chars().any(forbidden_in_text) {
            return Err(TrackerLoadError::BadText);
        }
        Ok(text)
    }

    fn texts(&mut self, max: usize) -> Result<Vec<String>, TrackerLoadError> {
        let count = self.count(max, 4)?;
        (0..count).map(|_| self.text()).collect()
    }
}
