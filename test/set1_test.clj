(ns set1-test
  (:use set1 clojure.test))

(def mushroom-hex   "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
(def mushroom-base64 "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")

(defn does-round-trip [x back convert]
  (is (= x (back (convert x)))))

(deftest conversions
  (is (= mushroom-base64 (bytes-to-base64 (hex-to-bytes mushroom-hex))))
  (does-round-trip mushroom-hex bytes-to-hex hex-to-bytes)
  (does-round-trip mushroom-base64 bytes-to-base64 base64-to-bytes)
  (is (= (bytes-to-string (hex-to-bytes mushroom-hex)) 
     "I'm killing your brain like a poisonous mushroom")))

(def xor-a "1c0111001f010100061a024b53535009181c")
(def xor-b "686974207468652062756c6c277320657965")
(def xor-result "746865206b696420646f6e277420706c6179")

(deftest xor
  (is (= (hex-to-bytes xor-result) 
         (xor-bytes (hex-to-bytes xor-a) 
                    (hex-to-bytes xor-b)))))

(def plaintext "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
(def ICE-cipher "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

(deftest xor-encode
  (is (= (hex-to-bytes ICE-cipher) 
         (repeat-xor-encode (string-to-bytes plaintext) (string-to-bytes "ICE")))))

(def p3-input "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

(score-text (second (solve-xor-cipher (hex-to-bytes p3-input))))



(def p4-input (load-hex-line-file "resources/4.txt"))

(deftest solve-xor
  (is (= 88 (first (solve-xor-cipher (hex-to-bytes p3-input)))))
  (is (= 53 (first (solve-many-xors p4-input)))))

(deftest hamming
  (is (= 37 (hamming-distance (string-to-bytes "this is a test")
                              (string-to-bytes "wokka wokka!!!")))))

(def p6-input (slurp-no-newlines "resources/6.txt"))

(deftest crack-repeating-xor
  (is (= "Terminator X: Bring the noise" 
         (bytes-to-string (crack-repeating-key-xor (base64-to-bytes p6-input))))))

(def p7-input (slurp-no-newlines "resources/7.txt"))
(def p7-key "YELLOW SUBMARINE")

(deftest aes
  (is (= "I'm back" 
           (subs (bytes-to-string (aes-decrypt 
                                    (base64-to-bytes p7-input) 
                                    (string-to-bytes p7-key))) 
                 0 8))))

(def p8-input (load-hex-line-file "resources/8.txt"))

(deftest module-tests
  (is (= 4 (number-of-duplicate-blocks (detect-ecb-mode p8-input)))))
