# Как собрать Aevum из публичного репозитория

Некоторые модули (governance, ZK-верификация, AML-консенсус) пока закрыты и не включены в этот репозиторий. Они **не нужны для майнинга**. Чтобы скомпилировать ноду, создайте заглушки.

## Быстрый старт

```bash
# 1. Клонируем
git clone https://github.com/aevum-foundation/aevum-public.git
cd aevum-public

# 2. Создаём заглушки для скрытых модулей
mkdir -p crates/aevum/src/oracle crates/aevum/src/vm

cat > crates/aevum/src/oracle/consensus.rs << 'STUB'
use crate::crypto::hash::Hash;
#[derive(Debug)] pub struct OracleConsensus;
impl OracleConsensus { pub fn new() -> Self { OracleConsensus } }
STUB

cat > crates/aevum/src/oracle/innocence.rs << 'STUB'
use crate::crypto::hash::Hash;
#[derive(Debug)] pub struct InnocenceManager;
impl InnocenceManager { pub fn new() -> Self { InnocenceManager } }
#[derive(Clone, Debug)] pub struct CrossChainRisk;
impl CrossChainRisk { pub fn new(_a: u32, _b: &str, _c: u64) -> Self { CrossChainRisk } }
STUB

cat > crates/aevum/src/oracle/governance.rs << 'STUB'
STUB

cat > crates/aevum/src/oracle/zk_juris.rs << 'STUB'
STUB

cat > crates/aevum/src/prisma/zk_accept.rs << 'STUB'
STUB

cat > crates/aevum/src/vm/zk_vm.rs << 'STUB'
STUB

cat > crates/aevum/src/oracle/mod.rs << 'STUB'
pub mod conscience;
pub mod governance;
pub mod jurisdiction;
pub mod zk_juris;
pub mod consensus;
pub mod innocence;
STUB

# 3. Собираем
cargo build --release -p aevum-node

# 4. Создаём адрес
./target/release/cli-wallet create-address

# 5. Запускаем майнинг
./target/release/aevum-node \
  --miner-key ВАШ_ПРИВАТНЫЙ_КЛЮЧ \
  --bootstrap-peers 186.246.14.202:9733
```

Проверка

```bash
curl http://localhost:19734/status
# Должно показать: {"height":..., "peers":..., "poh_tick":...}
```

Примечания

· Скрытые модули будут доступны как .so файлы после завершения тестирования
· Для майнинга достаточно CPU, GPU не требуется
· Комиссия: 0.01% от суммы перевода
· Telegram: https://t.me/aevumchain
