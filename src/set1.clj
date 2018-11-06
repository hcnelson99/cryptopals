(ns set1
  (:require [clojure.test :as t] clojure.set [clojure.string :as s])
  (:import java.util.Base64))

(defn hex-char-to-int [^Character c]
  (if (Character/isDigit c)
    (- (int c) (int \0))
    (+ (- (int (Character/toLowerCase c)) (int \a)) 
       10)))

(defn hex-pair-to-byte [[l h]]
  (+ (* h 16) l))

(defn hex-to-bytes [hex]
  (->> hex
      (partition 2)
      (mapv (fn [[x y]] (Integer/parseInt (str x y) 16)))))

(defn bytes-to-hex [hex]
  (apply str (map #(format "%02x" %) hex)))

(defn bytes-to-base64 [b]
  (.encodeToString (Base64/getEncoder) (byte-array b)))

(defn base64-to-bytes [^String s]
  (apply vector (.decode (Base64/getDecoder) (.getBytes s "UTF-8"))))

(defn xor-bytes [a b]
  (mapv bit-xor a b))


(defn most-frequent-characters [^String string n]
  (->> string
      (.toLowerCase)
      (frequencies)
      (sort-by val >)
      (map key)
      (take n)))

(def letter-frequencies 
{\a 0.08167 \b 0.01492 \c 0.02782 \d 0.04253 \e 0.12702 \f 0.02228 \g 0.02015 
 \h 0.06094 \i 0.06966 \j 0.00153 \k 0.00772 \l 0.04025 \m 0.02406 \n 0.06749 
 \o 0.07507 \p 0.01929 \q 9.5e-4 \r 0.05987 \s 0.06327 \t 0.09056 \u 0.02758 
 \v 0.00978 \w 0.0236 \x 0.0015 \y 0.01974 \z 7.4e-4})

(defn map-on-map-vals [f m]
  (zipmap (keys m) (map f (vals m))))

(def etaoin-shrdlu (into #{} "etaoin "))

(defn score-text [string]
  (let [most-freq (most-frequent-characters string (count etaoin-shrdlu))]
    (- (count (clojure.set/intersection etaoin-shrdlu (into #{} most-freq)))
       (count (into #{} (filter #(not (Character/isLetter ^Character %)) string)))) ))

(defn string-to-bytes [s]
  (mapv int s))

(defn bytes-to-string [b]
  (reduce str (map char b)))

(defn all-xors [b]
  (let [len (count b)]
    (map #(vector %
            (->> (repeat %)
                 (xor-bytes b)
                 (bytes-to-string))) 
         (range 256))))

(defn best-score [xors]
  (apply max-key (fn [[b t]] (score-text t)) xors))

(def b (hex-to-bytes "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))

(defn solve-xor-cipher [b]
  (best-score (all-xors b)))

(defn solve-many-xors [bs]
  (best-score (pmap solve-xor-cipher bs)))

(defn repeat-xor-encode [plaintext k]
  (xor-bytes plaintext (cycle k)))

(defn hamming-distance [a b]
  (reduce + (map #(Long/bitCount %) 
                 (xor-bytes a b))))

(defn slurp-no-newlines [filename]
  (apply str (line-seq (clojure.java.io/reader filename))))


(defn aes-decrypt [input-bytes key-bytes]
  (let [k (javax.crypto.spec.SecretKeySpec. (byte-array key-bytes) "AES")
        cipher (doto (javax.crypto.Cipher/getInstance "AES/ECB/PKCS5Padding")
           (.init javax.crypto.Cipher/DECRYPT_MODE k))]
    (.doFinal cipher (byte-array input-bytes))))


(defn average [coll]
  (/ (reduce + coll) (count coll)))

(defn score-key-size [byte-input key-size]
  (->> byte-input
       (partition key-size)
       (partition 2)
       (map #(/ (apply hamming-distance %) key-size))
       (average)))

(defn crack-repeating-key-xor [byte-input]
  (let [key-size (apply min-key #(score-key-size byte-input %) (range 2 41)) ]
    (->> byte-input
         (partition key-size)
         (apply mapv vector)
         (map (comp first solve-xor-cipher)))))

(defn load-hex-line-file [filename]
  (map hex-to-bytes (line-seq (clojure.java.io/reader filename))))

(defn number-of-duplicate-blocks [b]
  (apply + (filter #(> % 1) (map val (frequencies (partition 16 b))))))

(defn detect-ecb-mode [inputs]
  (apply max-key number-of-duplicate-blocks inputs))
