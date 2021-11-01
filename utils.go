/*
 * Copyright contributors to the IBM Security Verify Operator project
 */

package main

/*****************************************************************************/

import (
    "errors"
    "fmt"
    "strings"

    "github.com/go-logr/logr"

    apiv1  "k8s.io/api/core/v1"
)

/*****************************************************************************/

/*
 * Logging information.
 */

type LogInfo struct {
    log          *logr.Logger
    currentLevel int
    attributes   []interface{}
}

/*****************************************************************************/

/*
 * Add some debug trace based on the specified level and the current level.
 */

func (l *LogInfo)Log(level int, msg string, kvList ...interface{}) {

    if (l.currentLevel >= level) {
        (*l.log).Info(msg, append(l.attributes, kvList...)...)
    }
}

/*****************************************************************************/

/*
 * Add some debug trace based on the specified level and the current level.
 */

func (l *LogInfo)Error(err error, msg string, kvList ...interface{}) {
    (*l.log).Error(err, msg, append(l.attributes, kvList...)...)
}

/*****************************************************************************/

/*
 * Retrieve the base64 decoded piece of data from the supplied secret.
 */

func GetSecretData(secret *apiv1.Secret, name string) (string, error) {
    value, ok := secret.Data[name]

    if !ok {
        return "", errors.New(
                fmt.Sprintf("The field, %s, is not available in the " +
                    "secret: %s", name, secret.Name))
    }

    return strings.TrimSuffix(string(value), "\n"), nil
}

/*****************************************************************************/

