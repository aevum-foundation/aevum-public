use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum TaskCategory {
    GeneralCompute     = 0,
    ScientificCompute  = 1,
    FinancialCompute   = 2,
    AITraining         = 3,
    AIInference        = 4,
    EngineeringCompute = 5,
    CreativeCompute    = 6,
    CryptoCompute      = 7,
    Custom             = 255,
}

impl TaskCategory {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::GeneralCompute), 1 => Some(Self::ScientificCompute),
            2 => Some(Self::FinancialCompute), 3 => Some(Self::AITraining),
            4 => Some(Self::AIInference), 5 => Some(Self::EngineeringCompute),
            6 => Some(Self::CreativeCompute), 7 => Some(Self::CryptoCompute),
            255 => Some(Self::Custom), _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HwRequirements {
    pub min_gpu_vram_mb: u32, pub min_ram_mb: u32,
    pub requires_cuda: bool, pub requires_opencl: bool,
}

impl HwRequirements {
    pub fn satisfied_by(&self, vram: u32, ram: u32, cuda: bool, opencl: bool) -> bool {
        if self.min_gpu_vram_mb > vram { return false; }
        if self.min_ram_mb > ram { return false; }
        if self.requires_cuda && !cuda { return false; }
        if self.requires_opencl && !opencl { return false; }
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationPolicy { ZkOnly, Redundant { n: u8 }, Challenge, Hybrid { zk: bool, challenge: bool } }

impl VerificationPolicy {
    pub fn default_for(category: TaskCategory) -> Self {
        match category {
            TaskCategory::FinancialCompute | TaskCategory::CryptoCompute => Self::ZkOnly,
            TaskCategory::AITraining => Self::Redundant { n: 3 },
            TaskCategory::ScientificCompute | TaskCategory::EngineeringCompute => Self::Hybrid { zk: true, challenge: true },
            TaskCategory::CreativeCompute => Self::Redundant { n: 2 },
            _ => Self::Challenge,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExecutionPolicy {
    pub category: TaskCategory, pub hw: HwRequirements,
    pub deterministic: bool, pub max_runtime_ms: u64,
    pub priority_weight: u8, pub admission_weight: u8,
}

impl ExecutionPolicy {
    pub fn for_category(category: TaskCategory) -> Self {
        let hw = match category {
            TaskCategory::AITraining => HwRequirements { min_gpu_vram_mb: 8192, min_ram_mb: 16384, requires_cuda: true, ..Default::default() },
            TaskCategory::AIInference => HwRequirements { min_gpu_vram_mb: 4096, min_ram_mb: 8192, requires_cuda: true, ..Default::default() },
            TaskCategory::ScientificCompute | TaskCategory::EngineeringCompute => HwRequirements { min_gpu_vram_mb: 4096, min_ram_mb: 8192, ..Default::default() },
            TaskCategory::CreativeCompute => HwRequirements { min_gpu_vram_mb: 2048, min_ram_mb: 4096, ..Default::default() },
            _ => HwRequirements::default(),
        };
        Self { category, hw, deterministic: matches!(category, TaskCategory::CryptoCompute | TaskCategory::FinancialCompute), max_runtime_ms: 60_000, priority_weight: 50, admission_weight: 50 }
    }

    pub fn for_category_with_ns(category: TaskCategory, ns: Option<&NamespaceDescriptor>) -> Self {
        let mut policy = Self::for_category(category);
        if let Some(ns) = ns { policy.priority_weight = ns.priority_bias; policy.admission_weight = ns.congestion_bias; }
        policy
    }
}

#[derive(Clone, Debug)]
pub struct NamespaceDescriptor {
    pub id: [u8; 32], pub label: String, pub version: u16, pub category: TaskCategory,
    pub tags: Vec<u8>, pub priority_bias: u8, pub verification_bias: u8, pub congestion_bias: u8,
}

impl NamespaceDescriptor {
    pub fn id_from_label(label: &str, version: u16) -> [u8; 32] {
        let mut h = blake3::Hasher::new(); h.update(b"AEVUM_NAMESPACE_V2"); h.update(label.as_bytes()); h.update(&version.to_le_bytes());
        *h.finalize().as_bytes()
    }
    pub fn new(label: &str, version: u16, category: TaskCategory) -> Self {
        Self { id: Self::id_from_label(label, version), label: label.into(), version, category, tags: Vec::new(), priority_bias: 50, verification_bias: 0, congestion_bias: 50 }
    }
    pub fn with_priority(mut self, bias: u8) -> Self { self.priority_bias = bias.min(100); self }
    pub fn with_verification(mut self, bias: u8) -> Self { self.verification_bias = bias.min(100); self }
    pub fn with_congestion(mut self, bias: u8) -> Self { self.congestion_bias = bias.min(100); self }
}

pub struct NamespaceRegistry { namespaces: HashMap<[u8; 32], NamespaceDescriptor>, max_namespaces: usize }

impl NamespaceRegistry {
    pub fn new(max_namespaces: usize) -> Self { Self { namespaces: HashMap::with_capacity(max_namespaces), max_namespaces } }
    pub fn register(&mut self, ns: NamespaceDescriptor) -> Result<(), &'static str> {
        if self.namespaces.len() >= self.max_namespaces { return Err("registry full"); }
        if self.namespaces.contains_key(&ns.id) { return Err("namespace already exists"); }
        if ns.label.len() > 128 { return Err("label too long"); }
        if ns.version == 0 { return Err("version >= 1 required"); }
        if ns.priority_bias > 100 || ns.verification_bias > 100 || ns.congestion_bias > 100 { return Err("bias > 100"); }
        self.namespaces.insert(ns.id, ns); Ok(())
    }
    pub fn get(&self, id: &[u8; 32]) -> Option<&NamespaceDescriptor> { self.namespaces.get(id) }
    pub fn len(&self) -> usize { self.namespaces.len() }
    pub fn resolve_execution(&self, category: TaskCategory, namespace_id: Option<&[u8; 32]>) -> ExecutionPolicy {
        let ns = namespace_id.and_then(|id| self.namespaces.get(id));
        ExecutionPolicy::for_category_with_ns(category, ns)
    }
    pub fn resolve_verification(&self, category: TaskCategory, namespace_id: Option<&[u8; 32]>) -> VerificationPolicy {
        let base = VerificationPolicy::default_for(category);
        if let Some(ns) = namespace_id.and_then(|id| self.namespaces.get(id)) {
            return match ns.verification_bias { 0..=30 => base, 31..=70 => VerificationPolicy::Hybrid { zk: true, challenge: true }, _ => VerificationPolicy::ZkOnly };
        }
        base
    }
}

pub fn execution_fingerprint(category: TaskCategory, ns: Option<&NamespaceDescriptor>) -> [u8; 32] {
    let mut h = blake3::Hasher::new(); h.update(b"AEVUM_EXEC_FP_V2"); h.update(&[category as u8]);
    if let Some(ns) = ns { h.update(&ns.id); h.update(&[ns.priority_bias]); h.update(&[ns.verification_bias]); h.update(&[ns.congestion_bias]); }
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn category_from_u8() { assert_eq!(TaskCategory::from_u8(0), Some(TaskCategory::GeneralCompute)); assert_eq!(TaskCategory::from_u8(99), None); }
    #[test] fn financial_requires_zk() { assert_eq!(VerificationPolicy::default_for(TaskCategory::FinancialCompute), VerificationPolicy::ZkOnly); }
    #[test] fn namespace_id_versioned() { assert_eq!(NamespaceDescriptor::id_from_label("test", 1), NamespaceDescriptor::id_from_label("test", 1)); assert_ne!(NamespaceDescriptor::id_from_label("test", 1), NamespaceDescriptor::id_from_label("test", 2)); }
    #[test] fn registry_rejects_duplicate() { let mut r = NamespaceRegistry::new(10); let ns = NamespaceDescriptor::new("t", 1, TaskCategory::GeneralCompute); assert!(r.register(ns.clone()).is_ok()); assert!(r.register(ns).is_err()); }
}
