package core

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"sort"
	"strings"
)

const (
	ServerId  = 3558
	ServerKey = "lV8I5GhwxTC6k6MkQhzqSIR6Gol7uZuI"
)

// buildSignature 云技术部参数签名
// 1. 客户端发版前申请验证密钥salt，加密保存保证不会被破解（salt外部为appkey H5不能用客户端的appkey，内部为serverkey）。
// 2. 将URI参数内容升序排序拼接成一个字符串，Body内容当一整串内容放在最后位置；如：URI:a=1, b=2, c=3 排序后的顺序是 a=1b=2c=3 ,body内容为 {"abc":3}。
// 3. 将排序好的参数值拼装在一起，根据上面的示例得到的结果为：a=1b=2c=3{"abc":3}。不要有换行和空格。
// 4. 拼装的字符串前后加上app的salt后，使用MD5算法进行摘要，如：md5(salt+a=1b=2c=3{"abc":3}+salt)；
// @param query
// @param salt
// @param body
// @return string
// @return string
func buildSignature(query map[string]string, salt, body string) (string, string) {
	var (
		keys   []string
		buffer bytes.Buffer
	)
	for k, _ := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	buffer.WriteString(salt)
	for _, v := range keys {
		//signature字段不参与签名
		if v == "signature" {
			continue
		}
		buffer.WriteString(v)
		buffer.WriteByte('=')
		buffer.WriteString(query[v])
	}
	buffer.WriteString(body)
	buffer.WriteString(salt)
	h := md5.New()
	h.Write(buffer.Bytes())
	return strings.ToLower(hex.EncodeToString(h.Sum(nil))), buffer.String()
}

func GetInnerSignature(query map[string]string, body string) (string, string) {
	return buildSignature(query, ServerKey, body)
}
