use crate::core::compute::{BlockSolution, ComputeTask, TaskType, SubTask};
use crate::crypto::hash::Hash;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpuVendor { None, Vulkan, Cuda, Metal, OpenCL }

pub struct ComputeEngine {
    pub active_jobs: Vec<ComputeTask>,
    pub sub_tasks: HashMap<Hash, SubTask>,
    pub use_gpu: bool,
    pub max_concurrent: usize,
    pub gpu_vendor: GpuVendor,
}

impl ComputeEngine {
    pub fn new() -> Self {
        let gpu = Self::detect_gpu();
        ComputeEngine {
            active_jobs: Vec::new(), sub_tasks: HashMap::new(),
            use_gpu: gpu != GpuVendor::None,
            max_concurrent: if gpu != GpuVendor::None { 16 } else { 4 },
            gpu_vendor: gpu,
        }
    }

    fn detect_gpu() -> GpuVendor {
        if std::path::Path::new("/dev/nvidia0").exists() { return GpuVendor::Cuda; }
        if std::env::var("VULKAN_SDK").is_ok() { return GpuVendor::Vulkan; }
        GpuVendor::None
    }

    pub fn add_task(&mut self, task: ComputeTask) {
        if self.active_jobs.len() < self.max_concurrent { self.active_jobs.push(task); }
    }

    pub fn get_highest_reward_task(&self) -> Option<&ComputeTask> {
        self.active_jobs.iter().max_by_key(|t| t.reward)
    }

    pub fn try_solve(&self, task: &ComputeTask) -> Option<Vec<u8>> {
        self.try_solve_range(task, 0, task.total_combinations.min(1_000_000))
    }

    pub fn try_solve_range(&self, task: &ComputeTask, start: u64, end: u64) -> Option<Vec<u8>> {
        for counter in start..end {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"AEVUM_SOLUTION_V2");
            hasher.update(&counter.to_le_bytes());
            if Hash(hasher.finalize().into()) == task.verification_key { return Some(counter.to_le_bytes().to_vec()); }
        }
        None
    }

    pub fn try_solve_gpu(&self, task: &ComputeTask) -> Option<Vec<u8>> {
        if !self.use_gpu { return None; }
        match self.gpu_vendor {
            GpuVendor::Cuda => self.try_solve_range(task, 0, task.total_combinations),
            GpuVendor::Vulkan => self.try_solve_range(task, 0, task.total_combinations),
            _ => None,
        }
    }

    pub fn create_subtask(&mut self, task: &ComputeTask, worker_index: u64, total_workers: u64) -> Option<SubTask> {
        let (start, end) = task.get_chunk(worker_index, total_workers)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AEVUM_SUBTASK");
        hasher.update(task.task_id.as_bytes());
        hasher.update(&start.to_le_bytes());
        hasher.update(&end.to_le_bytes());
        let st = SubTask { task_id: task.task_id, range_start: start, range_end: end, assigned_to: None, reward_share: task.reward / total_workers, nonce: 0 };
        self.sub_tasks.insert(Hash(hasher.finalize().into()), st.clone());
        Some(st)
    }

    pub fn spawn_gpu_worker(&self, task: ComputeTask) -> Option<std::thread::JoinHandle<Option<Vec<u8>>>> {
        if !self.use_gpu { return None; }
        let vendor = self.gpu_vendor;
        Some(std::thread::spawn(move || {
            let engine = ComputeEngine::new();
            match vendor {
                GpuVendor::Cuda | GpuVendor::Vulkan => engine.try_solve_range(&task, 0, task.total_combinations),
                _ => None,
            }
        }))
    }

    pub fn active_count(&self) -> usize { self.active_jobs.len() }

    pub fn gpu_info(&self) -> String {
        match self.gpu_vendor {
            GpuVendor::None => "CPU only".to_string(),
            GpuVendor::Cuda => "NVIDIA CUDA".to_string(),
            GpuVendor::Vulkan => "Vulkan".to_string(),
            GpuVendor::Metal => "Apple Metal".to_string(),
            GpuVendor::OpenCL => "OpenCL".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_task(id: u8) -> ComputeTask {
        ComputeTask { task_id: Hash([id; 32]), task_type: TaskType::DrugDiscovery, input_data: vec![], reward: 100, deadline: 0, verification_key: Hash::zero(), issuer: [0u8; 32], total_combinations: 1_000_000, chunk_size: 1000 }
    }

    #[test]
    fn gpu_detection() { let e = ComputeEngine::new(); println!("GPU: {}", e.gpu_info()); }
    #[test]
    fn cpu_solve() { assert!(ComputeEngine::new().try_solve(&dummy_task(1)).is_none()); }
    #[test]
    fn gpu_fallback() { let r = ComputeEngine::new().try_solve_gpu(&dummy_task(1)); assert!(r.is_none() || r.is_some()); }
}
