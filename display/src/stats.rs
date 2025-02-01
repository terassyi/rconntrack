use conntrack::stats::Stats;
use serde::Serialize;

use crate::{Column, Row, ToColumnOptions, ToColumns};

#[derive(Debug, Default)]
pub struct StatsRow {}

impl StatsRow {
    pub fn new() -> StatsRow {
        StatsRow {}
    }
}

impl Row for StatsRow {
    fn row<C: Column, E: Serialize + ToColumns<C> + Send + Sync>(&self, entry: &E) -> String {
        let mut row_str = String::new();

        let columns = entry.to_columns(ToColumnOptions::default());

        for (i, c) in columns.iter().enumerate() {
            row_str += &c.column(false);
            if i != columns.len() - 1 {
                row_str += " ";
            }
        }
        row_str += "\n";

        row_str
    }

    fn header(&self) -> String {
        let header = [
            StatsColumn::Cpu(0),
            StatsColumn::Found(0),
            StatsColumn::Invalid(0),
            StatsColumn::Insert(0),
            StatsColumn::InsertFailed(0),
            StatsColumn::Drop(0),
            StatsColumn::EarlyDrop(0),
            StatsColumn::Error(0),
            StatsColumn::SearchRestart(0),
            StatsColumn::ClashResolve(0),
            StatsColumn::ChainTooLong(0),
        ];
        let mut row_str = String::new();
        for (i, c) in header.iter().enumerate() {
            row_str += &c.column(true);
            if i != header.len() - 1 {
                row_str += " ";
            }
        }
        row_str += "\n";

        row_str
    }
}

#[derive(Debug)]
pub enum StatsColumn {
    Cpu(u32),
    // Searched(Option<u32>),
    Found(u32),
    // New(Option<u32>),
    Invalid(u32),
    // Ignore(Option<u32>),
    // Delete(Option<u32>),
    // DeleteList(Option<u32>),
    Insert(u32),
    InsertFailed(u32),
    Drop(u32),
    EarlyDrop(u32),
    Error(u32),
    SearchRestart(u32),
    ClashResolve(u32),
    ChainTooLong(u32),
}

impl Column for StatsColumn {
    fn header(&self) -> String {
        match self {
            StatsColumn::Cpu(_) => String::from("CPU"),
            // StatsColumn::Searched(_) => String::from("SEARCHED"),
            StatsColumn::Found(_) => String::from("FOUND"),
            // StatsColumn::New(_) => String::from("NEW"),
            StatsColumn::Invalid(_) => String::from("INVALID"),
            // StatsColumn::Ignore(_) => String::from("IGNORE"),
            // StatsColumn::Delete(_) => String::from("DELETE"),
            // StatsColumn::DeleteList(_) => String::from("DELETE_LIST"),
            StatsColumn::Insert(_) => String::from("INSERT"),
            StatsColumn::InsertFailed(_) => String::from("INSERT_FAILED"),
            StatsColumn::Drop(_) => String::from("DROP"),
            StatsColumn::EarlyDrop(_) => String::from("EARLY_DROP"),
            StatsColumn::Error(_) => String::from("ERROR"),
            StatsColumn::SearchRestart(_) => String::from("SEARCH_RESTART"),
            StatsColumn::ClashResolve(_) => String::from("CLASH_RESOLVE"),
            StatsColumn::ChainTooLong(_) => String::from("CHAIN_TOO_LONG"),
        }
    }

    fn column(&self, header: bool) -> String {
        match self {
            StatsColumn::Cpu(v) => {
                if header {
                    format!("{:>3}", self.header())
                } else {
                    format!("{:>3}", v)
                }
            }
            StatsColumn::Found(v) => {
                if header {
                    format!("{:>5}", self.header())
                } else {
                    format!("{:>5}", v)
                }
            }
            StatsColumn::Invalid(v) => {
                if header {
                    format!("{:>7}", self.header())
                } else {
                    format!("{:>7}", v)
                }
            }
            StatsColumn::Insert(v) => {
                if header {
                    format!("{:>6}", self.header())
                } else {
                    format!("{:>6}", v)
                }
            }
            StatsColumn::InsertFailed(v) => {
                if header {
                    format!("{:>13}", self.header())
                } else {
                    format!("{:>13}", v)
                }
            }
            StatsColumn::Drop(v) => {
                if header {
                    format!("{:>4}", self.header())
                } else {
                    format!("{:>4}", v)
                }
            }
            StatsColumn::EarlyDrop(v) => {
                if header {
                    format!("{:>10}", self.header())
                } else {
                    format!("{:>10}", v)
                }
            }
            StatsColumn::Error(v) => {
                if header {
                    format!("{:>5}", self.header())
                } else {
                    format!("{:>5}", v)
                }
            }
            StatsColumn::SearchRestart(v) => {
                if header {
                    format!("{:>14}", self.header())
                } else {
                    format!("{:>14}", v)
                }
            }
            StatsColumn::ClashResolve(v) => {
                if header {
                    format!("{:>13}", self.header())
                } else {
                    format!("{:>13}", v)
                }
            }
            StatsColumn::ChainTooLong(v) => {
                if header {
                    format!("{:>14}", self.header())
                } else {
                    format!("{:>14}", v)
                }
            }
        }
    }
}

impl ToColumns<StatsColumn> for Stats {
    fn to_columns(&self, _opt: crate::ToColumnOptions) -> Vec<StatsColumn> {
        // Make sure the order is correct.
        vec![
            StatsColumn::Cpu(self.cpu as u32),
            StatsColumn::Found(self.found),
            StatsColumn::Invalid(self.invalid),
            StatsColumn::Insert(self.insert),
            StatsColumn::InsertFailed(self.insert_failed),
            StatsColumn::Drop(self.drop),
            StatsColumn::EarlyDrop(self.early_drop),
            StatsColumn::Error(self.error),
            StatsColumn::SearchRestart(self.search_restart),
            StatsColumn::ClashResolve(self.clash_resolve),
            StatsColumn::ChainTooLong(self.chain_too_long),
        ]
    }
}
