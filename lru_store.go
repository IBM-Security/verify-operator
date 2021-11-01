/*
 * Copyright contributors to the IBM Security Verify Operator project
 */

package main

/*
 * This file contains the logic for a simple LRU session store.  It is loosely
 * based on the quasoft/memstore package, and utilises the hasicorp/golang-lru 
 * package for the LRU cache.
 */

/*****************************************************************************/

import (
    "bytes"
    "encoding/base32"
    "encoding/gob"
    "fmt"
    "net/http"
    "strings"

    "github.com/hashicorp/golang-lru"
    "github.com/gorilla/securecookie"
    "github.com/gorilla/sessions"
)

/*****************************************************************************/

type LruCache struct {
    data *lru.Cache
}

/*****************************************************************************/

/*
 * Create a new LRU cache.
 */

func newCache() *LruCache {
    cache, err := lru.New(maxCacheSize)

    if err != nil {
        panic(fmt.Errorf("Failed to create the LRU cache: %v", err))
    }

    return &LruCache {
        data: cache,
    }
}

/*****************************************************************************/

/*
 * Retrieve the data associated with the specified key from the cache.
 */

func (c *LruCache) value(name string) (valueType, bool) {
    v, ok := c.data.Get(name)

    return v.(valueType), ok
}

/*****************************************************************************/

/*
 * Add the specified key, and associated data, to the cache.
 */

func (c *LruCache) setValue(name string, value valueType) {
    c.data.Add(name, value)
}

/*****************************************************************************/

/*
 * Remove the data associated with the specified key from the cache.
 */

func (c *LruCache) delete(name string) {
    c.data.Remove(name)
}

/*****************************************************************************/
/*****************************************************************************/

type LruStore struct {
    Codecs  []securecookie.Codec
    Options *sessions.Options
    cache   *LruCache
}

type valueType map[interface{}]interface{}

/*****************************************************************************/

/*
 * NewLruStore returns a new LruStore.
 *
 * Keys are defined in pairs to allow key rotation, but the common case is
 * to set a single authentication key and optionally an encryption key.
 *
 * The first key in a pair is used for authentication and the second for
 * encryption. The encryption key can be set to nil or omitted in the last
 * pair, but the authentication key is required in all pairs.
 *
 * It is recommended to use an authentication key with 32 or 64 bytes.
 * The encryption key, if set, must be either 16, 24, or 32 bytes to select
 * AES-128, AES-192, or AES-256 modes.
 *
 * Use the convenience function securecookie.GenerateRandomKey() to create
 * strong keys.
 */

func NewLruStore(keyPairs ...[]byte) *LruStore {

    store := LruStore{
        Codecs: securecookie.CodecsFromPairs(keyPairs...),
        Options: &sessions.Options{
            Path:   "/",
            MaxAge: 86400 * 30,
        },
        cache: newCache(),
    }

    store.MaxAge(store.Options.MaxAge)

    return &store
}

/*****************************************************************************/

/*
 * This function returns a session for the given name after adding it to the 
 * registry.
 *
 * It returns a new session if the sessions doesn't exist. Access IsNew on
 * the session to check if it is an existing session or a new one.
 *
 * It returns a new session and an error if the session exists but could
 * not be decoded.
 */

func (m *LruStore) Get(r *http.Request, name string) (*sessions.Session, error) {
    return sessions.GetRegistry(r).Get(m, name)
}

/*****************************************************************************/

/*
 * This function returns a session for the given name without adding it to 
 * the registry.
 *
 * The difference between New() and Get() is that calling New() twice will
 * decode the session data twice, while Get() registers and reuses the same
 * decoded session after the first call.
 */

func (m *LruStore) New(r *http.Request, name string) (*sessions.Session, error) {
    session := sessions.NewSession(m, name)
    options := *m.Options

    session.Options = &options
    session.IsNew   = true

    c, err := r.Cookie(name)
    if err != nil {

       /*
        * Cookie not found, this is a new session.
        */

        return session, nil
    }

    err = securecookie.DecodeMulti(name, c.Value, &session.ID, m.Codecs...)
    if err != nil {
        /*
         * The value could not be decrypted, consider this is a new session.
         */

        return session, err
    }

    v, ok := m.cache.value(session.ID)
    if !ok {
        /*
         * No value found in cache, don't set any values in session object.
         * Consider this a new session.
         */

        return session, nil
    }

    /*
     * Values found in session, this is not a new session.
     */

    session.Values = m.copy(v)
    session.IsNew  = false

    return session, nil
}

/*****************************************************************************/

/*
 * This function adds a single session to the response.
 *
 * Set Options.MaxAge to -1 or call MaxAge(-1) before saving the session to 
 * delete all values in it.
 */

func (m *LruStore) Save(
        r *http.Request, w http.ResponseWriter, s *sessions.Session) error {

    var cookieValue string

    if s.Options.MaxAge < 0 {
        cookieValue = ""

        m.cache.delete(s.ID)

        for k := range s.Values {
            delete(s.Values, k)
        }
    } else {
        if s.ID == "" {
            s.ID = strings.TrimRight(base32.StdEncoding.EncodeToString(
                                    securecookie.GenerateRandomKey(32)), "=")
        }

        encrypted, err := securecookie.EncodeMulti(s.Name(), s.ID, m.Codecs...)
        if err != nil {
            return err
        }

        cookieValue = encrypted

        m.cache.setValue(s.ID, m.copy(s.Values))
    }

    http.SetCookie(w, sessions.NewCookie(s.Name(), cookieValue, s.Options))

    return nil
}

/*****************************************************************************/

/* 
 * This function sets the maximum age for the store and the underlying cookie
 * implementation.  Individual sessions can be deleted by setting 
 * Options.MaxAge = -1 for that session.
 */

func (m *LruStore) MaxAge(age int) {
    m.Options.MaxAge = age

    /*
     * Set the maxAge for each securecookie instance.
     */

    for _, codec := range m.Codecs {
        if sc, ok := codec.(*securecookie.SecureCookie); ok {
            sc.MaxAge(age)
        }
    }
}

/*****************************************************************************/

/*
 * Make a copy of the session data.
 */

func (m *LruStore) copy(v valueType) valueType {

    var buf bytes.Buffer

    enc := gob.NewEncoder(&buf)
    dec := gob.NewDecoder(&buf)
    err := enc.Encode(v)

    if err != nil {
        panic(fmt.Errorf("Failed to copy the LruStore value. Encoding to gob " +
                            "failed: %v", err))
    }

    var value valueType

    err = dec.Decode(&value)

    if err != nil {
        panic(fmt.Errorf("Could not copy the LruStore value. Decoding from " +
                            "gob failed: %v", err))
    }

    return value
}

/*****************************************************************************/

