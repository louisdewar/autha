pub mod action;

pub type RedisPool = deadpool_redis::Pool;
pub type RedisConnection = deadpool_redis::Connection;

pub async fn get_redis_pool<C: deadpool_redis::redis::IntoConnectionInfo>(
    addr: C,
    max_connections: usize,
) -> RedisPool {
    let manager = deadpool_redis::Manager::new(addr).expect("creating redis client failed");
    RedisPool::builder(manager)
        .max_size(max_connections)
        .build()
        .expect("failed to create redis pool")
}
