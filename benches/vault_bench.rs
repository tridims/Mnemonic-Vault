use criterion::{black_box, criterion_group, criterion_main, Criterion};
use secure_mnemonic_vault::Vault;
use std::path::Path;

fn create_vault_benchmark(c: &mut Criterion) {
    c.bench_function("create_vault", |b| {
        b.iter(|| {
            let password = black_box(b"a good password");
            Vault::new(password)
        })
    });
}

fn set_data_benchmark(c: &mut Criterion) {
    let password = b"a good password";
    let mut vault = Vault::new(password);
    let mnemonic = "train forest limb pistol wide robot blur wrist all also galaxy veteran reveal foil depth couple custom high robust produce crawl victory glare vocal".to_string();
    let num_accounts = 5;

    c.bench_function("set_data", |b| {
        b.iter(|| {
            vault
                .set_data(black_box(mnemonic.clone()), black_box(num_accounts))
                .unwrap()
        })
    });
}

fn save_vault_benchmark(c: &mut Criterion) {
    let password = b"a good password";
    let mut vault = Vault::new(password);
    let mnemonic = "train forest limb pistol wide robot blur wrist all also galaxy veteran reveal foil depth couple custom high robust produce crawl victory glare vocal".to_string();
    vault.set_data(mnemonic, 5).unwrap();
    let file_path = Path::new("vault_benchmark.json");

    c.bench_function("save_vault", |b| {
        b.iter(|| {
            vault.save(black_box(file_path)).unwrap();
        })
    });
}

fn load_vault_benchmark(c: &mut Criterion) {
    let file_path = Path::new("vault_benchmark.json");

    c.bench_function("load_vault", |b| {
        b.iter(|| {
            Vault::load(black_box(file_path)).unwrap();
        })
    });
}

fn unlock_vault_benchmark(c: &mut Criterion) {
    let password = b"a good password";
    let file_path = Path::new("vault_benchmark.json");
    let mut vault = Vault::load(file_path).unwrap();

    c.bench_function("unlock_vault", |b| {
        b.iter(|| {
            vault.unlock(black_box(password)).unwrap();
        })
    });
}

fn change_password_benchmark(c: &mut Criterion) {
    let password = b"a good password";
    let new_password = b"another good new_password";

    let mut initial_vault = Vault::new(password);
    initial_vault.set_data(
        "train forest limb pistol wide robot blur wrist all also galaxy veteran reveal foil depth couple custom high robust produce crawl victory glare vocal".to_string(),
        5,
    ).unwrap();
    let encrypted_data = initial_vault.get_encrypted_data().unwrap().to_owned();

    c.bench_function("change_password", |b| {
        b.iter(|| {
            let mut vault = Vault::load_encrypted(encrypted_data.clone());
            vault.unlock(password).unwrap();
            vault.change_password(password, new_password).unwrap();
        });
    });
}

fn get_data_benchmark(c: &mut Criterion) {
    let password = b"a good password";
    let file_path = Path::new("vault_benchmark.json");
    let mut vault = Vault::load(file_path).unwrap();
    vault.unlock(password).unwrap();

    c.bench_function("get_data", |b| {
        b.iter(|| {
            vault.get_data().unwrap();
        })
    });
}

fn lock_vault_benchmark(c: &mut Criterion) {
    let password = b"a good password";
    let file_path = Path::new("vault_benchmark.json");
    let mut vault = Vault::load(file_path).unwrap();
    vault.unlock(password).unwrap();

    c.bench_function("lock_vault", |b| {
        b.iter(|| {
            vault.lock();
        })
    });
}

criterion_group!(
    benches,
    create_vault_benchmark,
    set_data_benchmark,
    save_vault_benchmark,
    load_vault_benchmark,
    unlock_vault_benchmark,
    change_password_benchmark,
    get_data_benchmark,
    lock_vault_benchmark
);
criterion_main!(benches);
