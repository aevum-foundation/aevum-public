use aevum::core::compute::{ComputeTask, TaskType};
use aevum::crypto::hash::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderStatus {
    Pending,
    Funded,
    InProgress,
    Proposed,
    Solved,
    Cancelled,
    Expired,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskOrder {
    pub order_id: Hash,
    pub customer: [u8; 32],
    pub task_type: TaskType,
    pub input_data_hash: Hash,
    pub reward: u64,
    pub total_combinations: u64,
    pub deadline_blocks: u64,
    pub status: OrderStatus,
    pub created_at: u64,
    pub assigned_miner: Option<[u8; 32]>,
    pub nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskSolution {
    pub order_id: Hash,
    pub chunk_start: u64,
    pub chunk_end: u64,
    pub solution: Vec<u8>,
    pub solver: [u8; 32],
    pub block_height: u64,
    pub zk_proof: Vec<u8>,
}

pub struct TaskMarket {
    pub orders: HashMap<Hash, TaskOrder>,
    pub solutions: HashMap<Hash, Vec<TaskSolution>>,
    pub fee_percent: u64,
    pub pool_fees: u64,
    max_orders: usize,
}

impl TaskMarket {
    pub fn new(fee_percent: u64) -> Self {
        TaskMarket {
            orders: HashMap::new(),
            solutions: HashMap::new(),
            fee_percent,
            pool_fees: 0,
            max_orders: 100_000,
        }
    }

    fn hash(data: &[&[u8]]) -> Hash {
        let mut hasher = blake3::Hasher::new();
        for d in data { hasher.update(d); }
        Hash(hasher.finalize().into())
    }

    /// Создать заказ
    pub fn place_order(
        &mut self,
        customer: [u8; 32],
        task: &ComputeTask,
        current_height: u64,
        nonce: u64,
    ) -> Hash {
        let input_hash = blake3::hash(&task.input_data);
        let order_id = Self::hash(&[
            b"AEVUM_ORDER_V2",
            &customer,
            input_hash.as_bytes(),
            &task.reward.to_le_bytes(),
            &current_height.to_le_bytes(),
            &nonce.to_le_bytes(),
        ]);

        let fee = task.reward * self.fee_percent / 10000;
        let net_reward = task.reward - fee;
        self.pool_fees += fee;

        let order = TaskOrder {
            order_id,
            customer,
            task_type: task.task_type.clone(),
            input_data_hash: Hash(input_hash.into()),
            reward: net_reward,
            total_combinations: task.total_combinations,
            deadline_blocks: current_height + task.deadline,
            status: OrderStatus::Pending,
            created_at: current_height,
            assigned_miner: None,
            nonce,
        };

        tracing::info!(
            "Order placed: id={}, reward={}, fee={}, total_comb={}, pool_fees={}",
            hex::encode(order_id.as_bytes()),
            net_reward, fee, task.total_combinations, self.pool_fees
        );

        if self.orders.len() >= self.max_orders {
            let expired: Vec<Hash> = self.orders.iter()
                .filter(|(_, o)| o.status == OrderStatus::Expired || o.status == OrderStatus::Cancelled)
                .map(|(id, _)| *id)
                .take(self.max_orders / 10)
                .collect();
            for id in expired {
                self.orders.remove(&id);
                self.solutions.remove(&id);
            }
        }

        self.orders.insert(order_id, order);
        order_id
    }

    pub fn fund_order(&mut self, order_id: &Hash) -> Result<(), &'static str> {
        let order = self.orders.get_mut(order_id).ok_or("Order not found")?;
        if order.status != OrderStatus::Pending {
            return Err("Order must be Pending to fund");
        }
        order.status = OrderStatus::Funded;
        tracing::info!("Order funded: {}", hex::encode(order_id.as_bytes()));
        Ok(())
    }

    pub fn accept_order(&mut self, order_id: &Hash, miner: [u8; 32]) -> Result<(), &'static str> {
        let order = self.orders.get_mut(order_id).ok_or("Order not found")?;
        if order.status != OrderStatus::Funded && order.status != OrderStatus::Pending {
            return Err("Order not available");
        }
        order.status = OrderStatus::InProgress;
        order.assigned_miner = Some(miner);
        tracing::info!("Order accepted by miner: {}", hex::encode(&miner));
        Ok(())
    }

    pub fn propose_solution(
        &mut self,
        order_id: &Hash,
        chunk_start: u64,
        chunk_end: u64,
        solution: Vec<u8>,
        solver: [u8; 32],
        block_height: u64,
        zk_proof: Vec<u8>,
    ) -> Result<Hash, &'static str> {
        let order = self.orders.get_mut(order_id).ok_or("Order not found")?;
        if order.status != OrderStatus::InProgress {
            return Err("Order not in progress");
        }
        if block_height > order.deadline_blocks {
            order.status = OrderStatus::Expired;
            return Err("Deadline passed");
        }

        let solution_id = Self::hash(&[
            b"AEVUM_SOLUTION_V2",
            order_id.as_bytes(),
            &chunk_start.to_le_bytes(),
            &chunk_end.to_le_bytes(),
            &solution,
        ]);

        let ts = TaskSolution {
            order_id: *order_id,
            chunk_start,
            chunk_end,
            solution,
            solver,
            block_height,
            zk_proof,
        };

        self.solutions.entry(*order_id).or_insert_with(Vec::new).push(ts);
        order.status = OrderStatus::Proposed;
        tracing::info!("Solution proposed: order={}", hex::encode(order_id.as_bytes()));
        Ok(solution_id)
    }

    /// Верифицировать решение (Proposed → Solved)
    pub fn verify_solution(&mut self, order_id: &Hash, solution_id: &Hash) -> Result<(), &'static str> {
        let order = self.orders.get_mut(order_id).ok_or("Order not found")?;
        if order.status != OrderStatus::Proposed {
            return Err("Order not in Proposed state");
        }
        // Проверяем что решение существует
        let solutions = self.solutions.get(order_id).ok_or("No solutions for order")?;
        if !solutions.iter().any(|s| {
            Self::hash(&[
                b"AEVUM_SOLUTION_V2",
                order_id.as_bytes(),
                &s.chunk_start.to_le_bytes(),
                &s.chunk_end.to_le_bytes(),
                &s.solution,
            ]) == *solution_id
        }) {
            return Err("Solution not found");
        }
        order.status = OrderStatus::Solved;
        tracing::info!("Solution verified, order solved: {}", hex::encode(order_id.as_bytes()));
        Ok(())
    }

    pub fn cancel_order(&mut self, order_id: &Hash) -> Result<(), &'static str> {
        let order = self.orders.get_mut(order_id).ok_or("Order not found")?;
        if order.status == OrderStatus::Solved {
            return Err("Already solved");
        }
        order.status = OrderStatus::Cancelled;
        tracing::info!("Order cancelled: {}", hex::encode(order_id.as_bytes()));
        Ok(())
    }

    pub fn available_orders(&self, current_height: u64) -> Vec<&TaskOrder> {
        self.orders.values()
            .filter(|o| o.status == OrderStatus::Pending || o.status == OrderStatus::Funded)
            .filter(|o| o.deadline_blocks > current_height)
            .collect()
    }

    pub fn best_order(&self, current_height: u64) -> Option<&TaskOrder> {
        self.available_orders(current_height)
            .into_iter()
            .max_by(|a, b| {
                let a_ratio = a.reward as f64 / a.total_combinations.max(1) as f64;
                let b_ratio = b.reward as f64 / b.total_combinations.max(1) as f64;
                a_ratio.partial_cmp(&b_ratio).unwrap_or(std::cmp::Ordering::Equal)
            })
    }

    pub fn order_count(&self) -> usize { self.orders.len() }
    pub fn solution_count(&self) -> usize { self.solutions.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_task(reward: u64, total: u64) -> ComputeTask {
        ComputeTask {
            task_id: Hash::zero(),
            task_type: TaskType::DrugDiscovery,
            input_data: vec![1, 2, 3],
            reward,
            deadline: 100,
            verification_key: Hash::zero(),
            issuer: [1u8; 32],
            total_combinations: total,
            chunk_size: (total / 1000).max(1),
        }
    }

    #[test]
    fn place_and_fund() {
        let mut market = TaskMarket::new(100);
        let task = make_task(1000, 1_000_000);
        let id = market.place_order([1u8; 32], &task, 0, 1);
        assert_eq!(market.order_count(), 1);
        assert_eq!(market.pool_fees, 10); // 1% от 1000
        let order = market.orders.get(&id).unwrap();
        assert_eq!(order.reward, 990);
        market.fund_order(&id).unwrap();
        assert_eq!(market.orders.get(&id).unwrap().status, OrderStatus::Funded);
    }

    #[test]
    fn full_cycle() {
        let mut market = TaskMarket::new(0);
        let task = make_task(500, 500_000);
        let id = market.place_order([1u8; 32], &task, 0, 1);
        market.fund_order(&id).unwrap();
        market.accept_order(&id, [9u8; 32]).unwrap();
        let sid = market.propose_solution(&id, 0, 1000, vec![1], [9u8; 32], 10, vec![]).unwrap();
        assert!(market.verify_solution(&id, &sid).is_ok());
        assert_eq!(market.orders.get(&id).unwrap().status, OrderStatus::Solved);
    }

    #[test]
    fn verify_fake_solution_fails() {
        let mut market = TaskMarket::new(0);
        let task = make_task(100, 1000);
        let id = market.place_order([1u8; 32], &task, 0, 1);
        market.fund_order(&id).unwrap();
        market.accept_order(&id, [9u8; 32]).unwrap();
        market.propose_solution(&id, 0, 10, vec![1], [9u8; 32], 10, vec![]).unwrap();
        let fake_id = Hash::zero();
        assert!(market.verify_solution(&id, &fake_id).is_err());
    }

    #[test]
    fn best_order_by_ratio() {
        let mut market = TaskMarket::new(0);
        market.place_order([1u8; 32], &make_task(1000, 10_000_000), 0, 1);
        market.place_order([2u8; 32], &make_task(100, 100_000), 0, 2);
        let best = market.best_order(0).unwrap();
        assert_eq!(best.customer, [2u8; 32]);
    }
}
