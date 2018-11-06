(defproject cryptopals "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.9.0"]
                 [criterium "0.4.4"]
                 [com.clojure-goes-fast/clj-async-profiler "0.1.3"]]
  :main ^:skip-aot set1
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
