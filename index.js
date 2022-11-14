const { buildEddsa, buildBabyjub } = require("circomlibjs");
const sha256 = require("sha256");
const bip39 = require("bip39");

const mnemonic = bip39.generateMnemonic();
const nonce = 1;
const ecdsaPrivateKey = bip39.mnemonicToSeed(mnemonic, nonce.toString());
const eddsaPrivateKey = sha256.x2(ecdsaPrivateKey + nonce);

// Generate EdDSA key pair
async function generateEdDSAKeyPair() {
  const eddsa = await buildEddsa();
  const babyJubjub = await buildBabyjub();
  const F = babyJubjub.F;
  const eddsaPublicKey = eddsa.prv2pub(eddsaPrivateKey);
  console.log("Private key : ", eddsaPrivateKey);
  console.log(
    "Public key :\nAx: ",
    F.toObject(eddsaPublicKey[0]).toString(16),
    "\nAy: ",
    F.toObject(eddsaPublicKey[1]).toString(16)
  );
}

// Sign message with EdDSA signature
async function signMessage() {
  const eddsa = await buildEddsa();
  const babyJubjub = await buildBabyjub();
  const F = babyJubjub.F;
  const message = F.e(1234);
  const signMessage = eddsa.signPoseidon(eddsaPrivateKey, message);
  console.log("R8x: ", F.toObject(signMessage.R8[0]).toString(16));
  console.log("R8y: ", F.toObject(signMessage.R8[1]).toString(16));
  console.log("S: ", signMessage.S.toString(16));
}
