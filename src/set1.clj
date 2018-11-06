(ns set1
  (:require  [clojure.set :refer [intersection]] [clojure.string :as s])
  (:import java.util.Base64 javax.crypto.spec.SecretKeySpec javax.crypto.Cipher))

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

(def etaoin-shrdlu (into #{} "etaoin "))

(defn score-text [string]
  (let [most-freq (most-frequent-characters string (count etaoin-shrdlu))]
    (- (count (intersection etaoin-shrdlu (into #{} most-freq)))
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
  (let [k (SecretKeySpec. (byte-array key-bytes) "AES")
        cipher (doto (Cipher/getInstance "AES/ECB/PKCS5Padding")
           (.init Cipher/DECRYPT_MODE k))]
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
