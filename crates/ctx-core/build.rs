// sqlx::migrate! embeds the SQL files at compile time; without this, editing a
// migration would not trigger a rebuild of this crate.
fn main() {
    println!("cargo:rerun-if-changed=../../migrations");
}
