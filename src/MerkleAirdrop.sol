//SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import { IERC20, SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title Merkle Airdrop - Airdrop tokens to users who can prove they are in a merkle tree
 * @author JR
 */

contract MerkleAirdrop is EIP712 {
  // ****************************
  // Type Declarations       ****
  // ****************************

  using ECDSA for bytes32;
  using SafeERC20 for IERC20;
  
  // ****************************
  // State variables         ****
  // ****************************

  IERC20 private i_airdropToken;
  bytes32 private immutable i_merkleRoot;
  mapping(address => bool) private s_hasClaimed;

  bytes32 private constant MESSAGE_TYPE_HASH = keccak256("AirdropClaim(address _account, uint256 _amount)");

  struct AirdropClaim {
    address account;
    uint256 amount;
  }

  // ****************************
  // Events                  ****
  // ****************************

  event Claimed(address account, uint256 amount);
  event MerkleRootUpdated(bytes32 newMerkleRoot);

  // ****************************
  // Errors                  ****
  // ****************************

  error MerkleAirdrop__InvalidProof();
  error MerkleAirdrop__AlreadyClaimed();
  error MerkleAirdrop__InvalidSignature();

  // ****************************
  // Functions               ****
  // ****************************

  constructor(
    bytes32 _merkleRoot, IERC20 _airdropToken
  ) EIP712("Merkle Airdrop", "1.0.0") {
    i_merkleRoot = _merkleRoot;
    i_airdropToken = _airdropToken;
  } 

  // ****************************
  // Functions External      ****
  // ****************************

  function claim(
    address _account,
    uint256 _amount,
    bytes32[] calldata _merkleProof,
    uint8 _v,
    bytes32 _r,
    bytes32 _s
  ) external {
    
    if(s_hasClaimed[_account]) {
      revert MerkleAirdrop__AlreadyClaimed();
    }

    if(!_isValidSignature(
      _account, 
      getMessageHash(_account, _amount),
      _v,
      _r,
      _s
      )) {
        revert MerkleAirdrop__InvalidSignature();
      }

      bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(_account, _amount))));
      
      if(!MerkleProof.verify(_merkleProof, i_merkleRoot, leaf)) {
        revert MerkleAirdrop__InvalidProof();
      }

      s_hasClaimed[_account] = true;

      emit Claimed(_account, _amount);

      i_airdropToken.safeTransfer(_account, _amount);
  }

  function getMerkleRoot() external view returns (bytes32) {
    return i_merkleRoot;
  }

  function getAirdropToken() external view returns (IERC20) {
    return i_airdropToken;
  }

  // ****************************
  // Functions Publics      ****
  // ****************************

  function getMessageHash(address _account, uint256 _amount) public view returns (bytes32) {
    return _hashTypedDataV4(
      keccak256(abi.encode(MESSAGE_TYPE_HASH, AirdropClaim({account: _account, amount: _amount})))
    );
  }

  // ****************************
  // Functions Internal      ****
  // ****************************

  function _isValidSignature(
    address _signer,
    bytes32 _digest,
    uint8 _v,
    bytes32 _r,
    bytes32 _s
  ) internal pure returns (bool) {
    (address actualSigner, ,) = ECDSA.tryRecover(_digest, _v, _r, _s);

    return (actualSigner == _signer);
  }
}