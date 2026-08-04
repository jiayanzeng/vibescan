use super::*;

#[derive(Debug)]
pub(super) struct UnitCollector {
    by_content_id: BTreeMap<ContentId, usize>,
    units: Vec<ScannableUnit>,
    paths_walked: u64,
    blobs_read: u64,
}

impl UnitCollector {
    pub(super) fn new() -> Self {
        Self {
            by_content_id: BTreeMap::new(),
            units: Vec::new(),
            paths_walked: 0,
            blobs_read: 0,
        }
    }

    pub(super) fn record_path_walked(&mut self) {
        self.paths_walked += 1;
    }

    pub(super) fn record_blob_read(&mut self) {
        self.blobs_read += 1;
    }

    pub(super) fn stats(&self) -> WalkStats {
        let materialized = self.units.len() as u64;
        WalkStats {
            paths_walked: self.paths_walked,
            blobs_read: self.blobs_read,
            unique_contents: materialized,
            units_materialized: materialized,
        }
    }

    pub(super) fn push(&mut self, unit: ScannableUnit) {
        if let Some(existing) = self.by_content_id.get(&unit.content_id).copied() {
            for location in unit.locations {
                merge_unit_location(&mut self.units[existing].locations, location);
            }
            return;
        }
        let index = self.units.len();
        self.by_content_id.insert(unit.content_id.clone(), index);
        self.units.push(unit);
    }

    pub(super) fn into_units(mut self) -> Vec<ScannableUnit> {
        for unit in &mut self.units {
            for location in &mut unit.locations {
                normalize_provenances(location);
            }
            unit.locations.sort_by(|left, right| {
                left.path
                    .cmp(&right.path)
                    .then_with(|| left.location_class.cmp(&right.location_class))
                    .then_with(|| {
                        provenance_sort_key(&left.provenance)
                            .cmp(&provenance_sort_key(&right.provenance))
                    })
            });
            unit.locations.dedup();
        }
        self.units
    }
}

pub(super) fn merge_unit_location(locations: &mut Vec<UnitLocation>, incoming: UnitLocation) {
    if let Some(existing) = locations
        .iter_mut()
        .find(|location| location.path == incoming.path)
    {
        existing.additional_provenance.push(incoming.provenance);
        existing
            .additional_provenance
            .extend(incoming.additional_provenance);
        normalize_provenances(existing);
    } else {
        locations.push(incoming);
    }
}

pub(super) fn normalize_provenances(location: &mut UnitLocation) {
    let mut provenances = std::iter::once(location.provenance.clone())
        .chain(location.additional_provenance.drain(..))
        .collect::<Vec<_>>();
    provenances.sort_by_key(provenance_sort_key);
    provenances.dedup();
    if let Some(primary) = provenances.first().cloned() {
        location.provenance = primary;
        location.additional_provenance = provenances.into_iter().skip(1).collect();
    }
}

pub(super) fn provenance_sort_key(provenance: &Provenance) -> (u8, String, String, String) {
    match provenance {
        Provenance::WorkingTree => (0, String::new(), String::new(), String::new()),
        Provenance::Commit { sha, author, date } => (
            1,
            sha.clone(),
            author.clone().unwrap_or_default(),
            date.clone().unwrap_or_default(),
        ),
    }
}

pub(super) fn content_id(content: &[u8]) -> ContentId {
    ContentId(Sha256::digest(content).into())
}
