package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"testing"
)

func Test_Sign_Verify(t *testing.T) {
	var privateKeyHex = "c47a0fb020f2066223e049ea342c5ea9e9844da92b3101d37ae115d7f13380d8"
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		t.Fatal(fmt.Sprintf("decode privateKey err %v", err))
		return
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		t.Fatal(fmt.Sprintf("ToECDSA privateKey err %v", err))
		return
	}
	publicKey := privateKey.PublicKey

	println("PrivateKey: ", hex.EncodeToString(privateKey.D.Bytes()))
	println("PublicKey: ", hex.EncodeToString(crypto.CompressPubkey(&publicKey)))
	println("Address: ", crypto.PubkeyToAddress(publicKey).Hex())
	// 要签名的数据
	msg := "coderlang 34+ 程序员，CTO，全栈工程师，搬砖 11 年，薪资翻 20 倍，公众号 coderlang 主理人"
	fmt.Println("Msg: ", msg)
	// 对数据进行哈希
	hash := crypto.Keccak256([]byte(msg))
	fmt.Println("Hash: ", hex.EncodeToString(hash))
	// 使用私钥对数据哈希进行签名
	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		fmt.Println("Error signing data:", err)
		return
	}

	// 打印签名
	fmt.Println("Signature: ", hex.EncodeToString(signature))
	sigToPub, err := crypto.SigToPub(hash, signature)
	if err != nil {
		fmt.Println("Error SigToPub:", err)
		return
	}

	println("SigToPub PublicKey: ", hex.EncodeToString(crypto.CompressPubkey(sigToPub)))

	invalidMsg := "coderlang 34+ 程序员，CTO，全栈工程师，搬砖 11 年，薪资翻 200 倍，公众号 coderlang 主理人"
	fmt.Println("InvalidMsg: ", invalidMsg)
	invalidSigToPub, err := crypto.SigToPub(crypto.Keccak256([]byte(invalidMsg)), signature)
	if err != nil {
		fmt.Println("Error SigToPub:", err)
		return
	}
	println("InvalidSigToPub PublicKey: ", hex.EncodeToString(crypto.CompressPubkey(invalidSigToPub)))
}

func Test_Encrypt_Decrypt(t *testing.T) {
	var privateKeyHex = "c47a0fb020f2066223e049ea342c5ea9e9844da92b3101d37ae115d7f13380d8"

	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		t.Fatal(fmt.Sprintf("decode privateKey err %v", err))
		return
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		t.Fatal(fmt.Sprintf("ToECDSA privateKey err %v", err))
		return
	}
	privateKeyECC := ecies.ImportECDSA(privateKey)

	println("PrivateKey: ", hex.EncodeToString(privateKeyECC.D.Bytes()))
	println("PublicKey: ", hex.EncodeToString(crypto.CompressPubkey(privateKeyECC.PublicKey.ExportECDSA())))

	msg := "coderlang 34+ 程序员，CTO，全栈工程师，搬砖 11 年，薪资翻 20 倍，公众号 coderlang 主理人"
	fmt.Println("Msg: ", msg)

	encrypt, err := ecies.Encrypt(rand.Reader, &privateKeyECC.PublicKey, []byte(msg), nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("PublicKey Encrypt: ", hex.EncodeToString(encrypt))

	decrypt, err := privateKeyECC.Decrypt(encrypt, nil, nil)
	if err != nil {
		t.Fatal(fmt.Sprintf("Decrypt err %v", err))
		return
	}

	if !bytes.Equal(decrypt, []byte(msg)) {
		t.Fatal("ecies: plaintext doesn't match message")
	}

	println("PrivateKey Decrypt: ", string(decrypt))
}
