(ns twitter.oauth
  (:use
   [clojure.test])
  (:require
   [oauth.client :as oa]
   [oauth.signature :as oas]
   [clojure.data.codec.base64 :as base64]
   [twitter.utils :as utils]
   [http.async.client :as http]
   [clojure.data.json :as json]))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

 (defrecord OauthCredentials
    [consumer
     #^String access-token
     #^String access-token-secret])

 (defrecord AppCredentials [#^String access-token])

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmulti sign-query
  (fn [credentials verb uri & {:keys [query]}]
    (type credentials)))

;; "takes oauth credentials and returns a map of the signing parameters"
(defmethod sign-query OauthCredentials
  [#^OauthCredentials oauth-creds verb uri & {:keys [query]}]
  (into (sorted-map)
        (merge {:realm "Twitter API"}
               (oa/credentials (:consumer oauth-creds)
                               (:access-token oauth-creds)
                               (:access-token-secret oauth-creds)
                               verb
                               uri
                               query))))


;; "takes oauth credentials and returns a map of the signing parameters"
(defmethod sign-query AppCredentials
  [#^AppCredentials oauth-creds verb uri & {:keys [query]}]
  nil)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmulti oauth-header-string
  (fn [signing-map oauth-creds & {:keys [url-encode?] :or {url-encode? true}}]
    (type oauth-creds)))

;; "creates the string for the oauth header's 'Authorization' value, url encoding each value"
(defmethod oauth-header-string OauthCredentials
  [signing-map oauth-creds & {:keys [url-encode?] :or {url-encode? true}}]
  (let [val-transform (if url-encode? oas/url-encode identity)
        s (reduce (fn [s [k v]] (format "%s%s=\"%s\"," s (name k) (val-transform (str v))))
                  "OAuth "
                  signing-map)]
    (.substring s 0 (dec (count s)))))

;; "creates the string for the oauth header's 'Authorization' value, url encoding each value"
(defmethod oauth-header-string AppCredentials
  [signing-map oauth-creds & {:keys [url-encode?] :or {url-encode? true}}]
  (str "Bearer " (:access-token oauth-creds)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn make-oauth-creds
  "creates an oauth object out of supplied params"
  [app-key app-secret user-token user-token-secret]

  (let [consumer (oa/make-consumer app-key
                                   app-secret
                                   "https://twitter.com/oauth/request_token"
                                   "https://twitter.com/oauth/access_token"
                                   "https://twitter.com/oauth/authorize"
                                   :hmac-sha1)]
    (OauthCredentials. consumer user-token user-token-secret)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn make-app-creds
  "creates an oauth object out of just app credentials"
  [app-key app-secret]
  (let [bearer-creds (str app-key ":" app-secret)
        bearer-creds-enc (utils/str-as-bytearray-conv base64/encode bearer-creds)]
    (with-open [client (http/create-client)]
      (let [response (-> (http/POST client "https://api.twitter.com/oauth2/token"
                                    :body "grant_type=client_credentials"
                                    :headers {:Authorization (str "Basic " bearer-creds-enc)
                                              :Content-Type "application/x-www-form-urlencoded;charset=UTF-8"})
                         (http/await)
                         (http/string)
                         (json/read-json))
            {:keys [token_type access_token errors]} response]
        (if (= token_type "bearer")
          (->AppCredentials access_token)
          (throw (Exception. (format "Failed app authorization: %s" errors))))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
