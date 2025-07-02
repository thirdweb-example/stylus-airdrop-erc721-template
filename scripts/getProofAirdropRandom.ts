import { readFileSync } from "fs";
import { MerkleTree } from "@thirdweb-dev/merkletree";
import { ethers } from "ethers";
import keccak256 from "keccak256";

const TARGET_RECIPIENT = "0x..";

const { root, recips, amts } = JSON.parse(
  readFileSync("airdropRoot.json", "utf8") // this file should be present -- generate tree first by running generateRootAirdropRandom.ts
);

const leaves = recips.map((addr: string, idx: number) =>
  ethers.utils.solidityKeccak256(["address", "uint256"], [addr, amts[idx]])
);
const tree = new MerkleTree(leaves, keccak256, { sortPairs: true });

const idx = recips.findIndex(
  (a: string) => a.toLowerCase() === TARGET_RECIPIENT.toLowerCase()
);
if (idx === -1) throw new Error("address not in list");

const proof = tree.getHexProof(leaves[idx]);

console.log(JSON.stringify({ root, proof, amount: amts[idx] }, null, 2));
