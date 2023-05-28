use bip39::{Language, Mnemonic, MnemonicType};

pub fn generate() -> String {
    let result = Mnemonic::new(MnemonicType::Words12, Language::English);

    result.into_phrase()
}

pub const fn length() -> usize {
    12
}
