use super::*;

#[derive(Debug, Default)]
pub(super) struct Baseline {
    ids: BTreeSet<FindingId>,
}

impl Baseline {
    pub(super) fn load(path: Option<&Path>) -> Result<Self, CoreError> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        if !path.exists() {
            return Err(CoreError::ConfiguredPathMissing {
                kind: "baseline",
                path: path.to_path_buf(),
            });
        }

        let content = fs::read_to_string(path).map_err(CoreError::Io)?;
        if let Ok(scan_result) = serde_json::from_str::<ScanResult>(&content) {
            return Ok(Self {
                ids: scan_result
                    .findings
                    .into_iter()
                    .map(|finding| finding.id)
                    .collect(),
            });
        }

        let ids = serde_json::from_str::<Vec<String>>(&content)
            .map_err(CoreError::Json)?
            .into_iter()
            .map(FindingId)
            .collect();
        Ok(Self { ids })
    }

    pub(super) fn contains(&self, id: &FindingId) -> bool {
        self.ids.contains(id)
    }
}

pub(super) fn load_detector(custom_rules_path: Option<&Path>) -> Result<Detector, CoreError> {
    let Some(path) = custom_rules_path else {
        return Detector::default_rules().map_err(CoreError::Detector);
    };
    if !path.exists() {
        return Err(CoreError::ConfiguredPathMissing {
            kind: "custom rules",
            path: path.to_path_buf(),
        });
    }
    let custom = fs::read_to_string(path).map_err(CoreError::Io)?;
    Detector::default_rules_with_custom_toml(&custom).map_err(CoreError::Detector)
}
