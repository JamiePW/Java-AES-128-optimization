# Java-AES-128-optimization  
密码学实验综合作业1——对称密码算法的优化  
Term Project 1 of Experiments of Cryptography - Optimization of Symmetric Cryptographic Algorithms   

使用Java语言实现AES-128密码算法的查表优化，经测试加密提速156.1%，解密算法提速179.2%  
Using Java to implement the AES-128 lookup table optimization, tested encryption speedup 156.1%, decryption speedup 179.2%  
References: https://zhuanlan.zhihu.com/p/42264499  

源代码文件说明：  

AES.java 普通的AES算法 original AES-128  
AES-Tbox.java 优化后的AES算法 optimized AES-128  

另：需要调用BigInteger
