//========================================================================
//
// SignatureInfo.cc
//
// This file is licensed under the GPLv2 or later
//
// Copyright 2015 André Guerreiro <aguerreiro1985@gmail.com>
// Copyright 2015 André Esser <bepandre@hotmail.com>
// Copyright 2017 Hans-Ulrich Jüttner <huj@froreich-bioscientia.de>
// Copyright 2017 Albert Astals Cid <aacid@kde.org>
//
//========================================================================

#include <config.h>

#include "SignatureInfo.h"
#include "goo/gmem.h"
#include <stdlib.h>
#include <string.h>
#include <seccomon.h>
#include <secder.h>

#ifdef ENABLE_NSS3
    #include <hasht.h>
#include <secder.h>
#include <iostream>

#else
    static const int HASH_AlgNULL = -1;
#endif

/* Constructor & Destructor */

SignatureInfo::SignatureInfo()
{
  sig_status = SIGNATURE_NOT_VERIFIED;
  cert_status = CERTIFICATE_NOT_VERIFIED;
  signer_name = nullptr;
  signer_cert_before = 0;
  //signer_cert = ;
  subject_dn = nullptr;
  hash_type = HASH_AlgNULL;
  signing_time = 0;
  sig_subfilter_supported = false;
}

SignatureInfo::SignatureInfo(SignatureValidationStatus sig_val_status, CertificateValidationStatus cert_val_status)
{
  sig_status = sig_val_status;
  cert_status = cert_val_status;
  signer_name = nullptr;
  signer_cert_before = 0;
  //signer_cert;
  subject_dn = nullptr;
  hash_type = HASH_AlgNULL;
  signing_time = 0;
  sig_subfilter_supported = false;
}

SignatureInfo::~SignatureInfo()
{
  free(signer_name);
}

/* GETTERS */

SignatureValidationStatus SignatureInfo::getSignatureValStatus()
{
  return sig_status;
}

CertificateValidationStatus SignatureInfo::getCertificateValStatus()
{
  return cert_status;
}

const char *SignatureInfo::getSignerName()
{
  return signer_name;
}

time_t parseDate(SECItem);

time_t parseDate(SECItem date)
{

    PRTime time;
    SECStatus rv;

    switch (date.type) {
        case siUTCTime:
            rv = DER_UTCTimeToTime(&time, &date);
            break;
        case siGeneralizedTime:
            rv = DER_GeneralizedTimeToTime(&time, &date);
            break;
        default:
            printf("devuelve 0");
            return 0;
    }

    if (rv != SECSuccess)
        return 0;
    return static_cast<time_t>(time/1000000);

}

time_t SignatureInfo::getSignerCertBefore()
{
  return parseDate(signer_cert.validity.notBefore);
  //return signer_cert_before;
}

time_t SignatureInfo::getSignerCertAfter() {
    //if (!signer_cert)
    //    return 0;

    PRTime time;
    SECStatus rv;
    SECItem notBefore = signer_cert.validity.notAfter;

    switch (notBefore.type) {
        case siUTCTime:
            rv = DER_UTCTimeToTime(&time, &notBefore);
            break;
        case siGeneralizedTime:
            rv = DER_GeneralizedTimeToTime(&time, &notBefore);
            break;
        default:
            printf("devuelve 0");
            return 0;
    }

    if (rv != SECSuccess)
        return 0;
    return static_cast<time_t>(time/1000000);
}

const char *SignatureInfo::getSubjectDN()
{
  return subject_dn;
}

int SignatureInfo::getHashAlgorithm()
{
  return hash_type;
}

time_t SignatureInfo::getSigningTime()
{
  return signing_time;
}

/* SETTERS */

void SignatureInfo::setSignatureValStatus(enum SignatureValidationStatus sig_val_status)
{
  sig_status = sig_val_status;
}

void SignatureInfo::setCertificateValStatus(enum CertificateValidationStatus cert_val_status)
{
  cert_status = cert_val_status;
}

void SignatureInfo::setSignerName(char *signerName)
{
  free(signer_name);
  signer_name = signerName;
}

void SignatureInfo::setSignerCertBefore(time_t notBeforeTime)
{
  signer_cert_before = notBeforeTime;
}

void SignatureInfo::setSignerCert(CERTCertificate cert) {
  signer_cert = cert;
}

void SignatureInfo::setSubjectDN(const char *subjectDN)
{
  subject_dn = subjectDN;
}

void SignatureInfo::setHashAlgorithm(int type)
{
  hash_type = type;
}

void SignatureInfo::setSigningTime(time_t signingTime)
{
  signing_time = signingTime;
}
