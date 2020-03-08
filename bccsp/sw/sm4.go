/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package sw

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"fmt"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/tjfoc/gmsm/sm4"
)


//SM4	一轮加密实现
func SM4Encrypt(key, src []byte) ([]byte, error) {
	dst := make([]byte, len(src))
	sm4.EncryptBlock(key, dst, src)
	return dst, nil
}

// SM4	一轮解密实现
func SM4Decrypt(key, src []byte) ([]byte, error) {

	dst := make([]byte, len(src))
	sm4.DecryptBlock(key, dst, src)
	return dst, nil
}



//pkcs5 padding
func pkcs5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}
//pkcs5 unpadding
func pkcs5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func sm4CBCEncrypt(key, iv, plainText []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	originalData := pkcs5Padding(plainText, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(originalData))
	blockMode.CryptBlocks(encrypted, originalData)
	return encrypted, nil
}

func sm4CBCDecrypt(key, iv, cipherText []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(cipherText))
	blockMode.CryptBlocks(origData, cipherText)
	origData = pkcs5UnPadding(origData)
	return origData, nil
}
//SM4-CBC Encrypt
func SM4CBCEncrypt(key,iv,data []byte) ([]byte, error)  {

	return sm4CBCEncrypt(key,iv,data)
}
//SM4-CBC Decrypt
func SM4CBCDecrypt(key,iv,encrpteddata []byte) ([]byte, error)  {

	return sm4CBCDecrypt(key,iv,encrpteddata)
}

type gmsm4Encryptor struct{}

//实现 Encryptor 接口
func (*gmsm4Encryptor) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) (ciphertext []byte, err error) {

	switch o := opts.(type) {

	case *bccsp.SM4CBCModeOpts:
		// sm4 in CBC mode with iv

		if len(o.IV) == 0 {
			return nil, errors.New("Invalid options. sm4-IV shoule be given")
		}else {
			return SM4CBCEncrypt(k.(*gmsm4PrivateKey).privKey,o.IV,plaintext)
		}

	default:
		return nil, fmt.Errorf("Mode not recognized [%s]", opts)
	}

}

type gmsm4Decryptor struct{}

//实现 Decryptor 接口
func (*gmsm4Decryptor) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) (plaintext []byte, err error) {

	//return SM4Decrypt(k.(*gmsm4PrivateKey).privKey, ciphertext)

	switch o :=opts.(type) {

	case *bccsp.SM4CBCModeOpts:

		return SM4CBCDecrypt(k.(*gmsm4PrivateKey).privKey,o.IV,ciphertext)

		//return AESCBCPKCS7Decrypt(k.(*aesPrivateKey).privKey, ciphertext)
	default:
		return nil, fmt.Errorf("Mode not recognized [%s]", opts)
	}

}
