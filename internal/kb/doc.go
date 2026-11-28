// Package kb explains identity providers' own error codes in plain English.
//
// The knowledge lives in one data file, codes.json, embedded in the
// binary, so ssotrace stays offline and a new code is a one-file change.
// Each entry names a vendor and either a code (such as AADSTS50105) or,
// for providers that show sentences instead of codes, an exact message
// (such as Keycloak's "Client not found."), with its cause and fix.
//
// Entries describe stable, documented error codes and messages only:
// nothing here depends on a vendor's API.
package kb
