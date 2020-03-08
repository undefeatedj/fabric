package sw
import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/tjfoc/gmsm/sm4"
	"log"

	"testing"
)
//1轮加解密
func TestSM4EncryptAndDecrypt(t *testing.T) {
	//加密部分测试

	//sm4密钥长度=128位
	key :=  []byte("0123456789012345")

	//随机生成128位密钥

	rand.Reader.Read(key)

	fmt.Printf("key = %x\n",key)

	//明文长度=128位

	var ptext = []byte("1234567890123456")

	//sm4encrypt

	encrypted, encErr := SM4Encrypt(key, ptext)

	//输出密文

	fmt.Printf("encrypted = %x\n",encrypted)

	if encErr != nil {
		t.Fatalf("Error encrypting '%s': %s", ptext, encErr)
	}

	//解密

	decrypted, dErr := SM4Decrypt(key, encrypted)

	//输出解密后的消息decrypted

	fmt.Printf("decrypted = %x\n",decrypted)

	//将明文转为16进制->encoded

	encoded := hex.EncodeToString(ptext)

	//然后将encoded输出

	fmt.Println("encoded is \t",encoded)

	if dErr != nil {
		t.Fatalf("Error decrypting the encrypted '%s': %v", ptext, dErr)
	}


	if string(ptext[:]) != string(decrypted[:]) {
		t.Fatal("Decrypt( Encrypt( ptext ) ) != ptext: Ciphertext decryption with the same key must result in the original plaintext!")
	}else{
		fmt.Println("解密成功！")
	}

}


func TestSM4CBCEncryptAndDecrypt(t *testing.T) {
	// 128比特密钥
	key := []byte("1234567890abcdef")
	// 128比特iv
	iv := make([]byte, sm4.BlockSize)
	data := []byte("Tongji Fintech Research Institute")
	ciphertxt,err := SM4CBCEncrypt(key,iv, data)
	if err != nil{
		log.Fatal(err)
	}
	fmt.Printf("加密结果: %x\n", ciphertxt)

	originaldata, err := SM4CBCDecrypt(key,iv,ciphertxt)
	if err != nil{
		log.Fatal(err)
	}

	fmt.Printf("解密结果: %x\n", originaldata)
	assert.Equal(t,data,originaldata)
	fmt.Println(assert.Equal(t,data,originaldata))


}