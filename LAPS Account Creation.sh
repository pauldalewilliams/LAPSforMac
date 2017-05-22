#!/bin/sh
####################################################################################################
#
#   MIT License
#
#   Copyright (c) 2016 University of Nebraska–Lincoln
#
#	Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in all
#   copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#   SOFTWARE.
#
####################################################################################################
#
# HISTORY
#
#	Version: 1.2
#
#	- 05/04/2016 Created by Phil Redfern
#   - 05/06/2016 Updated by Phil Redfern, improved local logging and security update.
#   - 05/16/2016 Updated by Phil Redfern, added logic for FileVault Encryption
#
#   - This script will create a local Administrator account to be used with LAPS.
#
####################################################################################################
#
# DEFINE VARIABLES & READ IN PARAMETERS
#
####################################################################################################

# HARDCODED VALUES SET HERE
apiURL="https://jss.unl.edu:8443"
LogLocation="/Library/Logs/Casper_LAPS.log"
apiUser=""
apiPass=""
LAPSuser=""
LAPSuserDisplay=""
newPass=""
hideLAPSuser=""
LAPSrunEvent=""

# CHECK TO SEE IF A VALUE WAS PASSED IN PARAMETER 4 AND, IF SO, ASSIGN TO "apiUser"
if [ "$4" != "" ] && [ "$apiUser" == "" ]; then
    apiUser=$4
fi

# CHECK TO SEE IF A VALUE WAS PASSED IN PARAMETER 5 AND, IF SO, ASSIGN TO "apiPass"
if [ "$5" != "" ] && [ "$apiPass" == "" ]; then
    apiPass=$5
fi

# CHECK TO SEE IF A VALUE WAS PASSED IN PARAMETER 6 AND, IF SO, ASSIGN TO "LAPSuser"
if [ "$6" != "" ] && [ "$LAPSuser" == "" ]; then
    LAPSuser=$6
fi

# CHECK TO SEE IF A VALUE WAS PASSED IN PARAMETER 7 AND, IF SO, ASSIGN TO "LAPSuserDisplay"
if [ "$7" != "" ] && [ "$LAPSuserDisplay" == "" ]; then
    LAPSuserDisplay=$7
fi

# CHECK TO SEE IF A VALUE WAS PASSED IN PARAMETER 8 AND, IF SO, ASSIGN TO "newPass"
if [ "$8" != "" ] && [ "$newPass" == "" ]; then
    newPass=$8
fi

# CHECK TO SEE IF A VALUE WAS PASSED IN PARAMETER 9 AND, IF SO, ASSIGN TO "hideLAPSuser"
if [ "${9}" != "" ] && [ "$hideLAPSuser" == "" ]; then
    hideLAPSuser="${9}"
fi

# CHECK TO SEE IF A VALUE WAS PASSED IN PARAMETER 10 AND, IF SO, ASSIGN TO "LAPSrunEvent"
if [ "${10}" != "" ] && [ "$LAPSrunEvent" == "" ]; then
    LAPSrunEvent="${10}"
fi

####################################################################################################
#
# SCRIPT CONTENTS - DO NOT MODIFY BELOW THIS LINE
#
####################################################################################################

udid=$(/usr/sbin/system_profiler SPHardwareDataType | /usr/bin/awk '/Hardware UUID:/ { print $3 }')
xmlString="<?xml version=\"1.0\" encoding=\"UTF-8\"?><computer><extension_attributes><extension_attribute><name>LAPS</name><value>$newPass</value></extension_attribute></extension_attributes></computer>"
extAttName="\"LAPS\""

# Logging Function for reporting actions
ScriptLogging(){

DATE=`date +%Y-%m-%d\ %H:%M:%S`
LOG="$LogLocation"

echo "$DATE" " $1" >> $LOG
}

ScriptLogging "======== Starting LAPS Account Creation ========"
ScriptLogging "Checking parameters."

# Verify parameters are present
if [ "$apiUser" == "" ]; then
    ScriptLogging "Error:  The parameter 'API Username' is blank.  Please specify a user."
    echo "Error:  The parameter 'API Username' is blank.  Please specify a user."
    ScriptLogging "======== Aborting LAPS Account Creation ========"
    exit 1
fi

if [ "$apiPass" == "" ]; then
    ScriptLogging "Error:  The parameter 'API Password' is blank.  Please specify a password."
    echo "Error:  The parameter 'API Password' is blank.  Please specify a password."
    ScriptLogging "======== Aborting LAPS Account Creation ========"
    exit 1
fi

if [ "$LAPSuser" == "" ]; then
    ScriptLogging "Error:  The parameter 'LAPS Account Shortname' is blank.  Please specify a user to create."
    echo "Error:  The parameter 'LAPS Account Shortname' is blank.  Please specify a user to create."
    ScriptLogging "======== Aborting LAPS Account Creation ========"
    exit 1
fi

if [ "$LAPSuserDisplay" == "" ]; then
    ScriptLogging "Error:  The parameter 'LAPS Account Displayname' is blank.  Please specify a user to create."
    echo "Error:  The parameter 'LAPS Account Displayname' is blank.  Please specify a user to create."
    ScriptLogging "======== Aborting LAPS Account Creation ========"
    exit 1
fi

if [ "$newPass" == "" ]; then
    ScriptLogging "Error:  The parameter 'LAPS Password Seed' is blank.  Please specify a password to seed."
    echo "Error:  The parameter 'LAPS Password Seed' is blank.  Please specify a password to seed."
    ScriptLogging "======== Aborting LAPS Account Creation ========"
    exit 1
fi

#Verify newPass meets complexity requirements
# 1. No repeated characters
# 2. No sequences of 3 or more characters
# 3. Has at least one number, symbol, uppercase letter, and lowercase letter
CheckPass () {
    echo "$newPass" |
    grep -Ev '(.)\1+' |
    grep -iv 'abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn' |
    grep -iv 'mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz' |
    grep -iv 'zyx|yxw|xwv|wvu|vut|uts|tsr|srq|rqp|qpo|pon|onm' |
    grep -iv 'nml|mlk|lkj|kji|jih|ihg|hgf|gfe|fed|edc|dcb|cba' |
    grep -v '012|123|234|345|456|567|678|789' |
    grep -v '987|876|765|654|543|432|321|210' |
    grep '[0-9]' | grep '[!@#_=]' | grep '[A-Z]' | grep '[a-z]'
}
if [ "$(CheckPass)" == "" ]; then
    ScriptLogging "Error:  The parameter 'LAPS Password Seed' does not meet complexity requirements.  Please use a different password."
    echo "Error:  The parameter 'LAPS Password Seed' does not meet complexity requirements.  Please use a different password."
    ScriptLogging "======== Aborting LAPS Account Creation ========"
    exit 1
fi

if [ "$hideLAPSuser" == "" ]; then
    ScriptLogging "Error:  The parameter 'Hide LAPS User' is blank.  Please specify a 0 to show the user or a 1 to hide the user."
    echo "Error:  The parameter 'Hide LAPS User' is blank.  Please specify a 0 to show the user or a 1 to hide the user."
    ScriptLogging "======== Aborting LAPS Account Creation ========"
    exit 1
elif [ "$hideLAPSuser" != "0" ] && [ "$hideLAPSuser" != "1" ]; then
    ScriptLogging "Error:  The parameter 'Hide LAPS User' is invalid.  Please specify a 0 to show the user or a 1 to hide the user."
    echo "Error:  The parameter 'Hide LAPS User' is invalid.  Please specify a 0 to show the user or a 1 to hide the user."
    ScriptLogging "======== Aborting LAPS Account Creation ========"
    exit 1
fi

if [ "$LAPSrunEvent" == "" ]; then
    ScriptLogging "Error:  The parameter 'LAPS Run Event' is blank.  Please specify a Custom LAPS Run Event."
    echo "Error:  The parameter 'LAPS Run Event' is blank.  Please specify a Custom LAPS Run Event."
    ScriptLogging "======== Aborting LAPS Account Creation ========"
    exit 1
fi

# Verify resetUser is not a local user on the computer
checkUser=`dseditgroup -o checkmember -m $LAPSuser localaccounts | awk '{ print $1 }'`

if [[ "$checkUser" = "yes" ]]; then
    ScriptLogging "Error: $LAPSuser already exists as a local user on the Computer"
    echo "Error: $LAPSuser already exists as a local user on the Computer"
    ScriptLogging "======== Aborting LAPS Account Creation ========"
    exit 1
else
    ScriptLogging "$LAPSuser is not a local user on the Computer, proceeding..."
    echo "$LAPSuser is not a local user on the Computer, proceeding..."
fi

ScriptLogging "Parameters Verified."

# Identify the location of the jamf binary for the jamf_binary variable.
CheckBinary (){
# Identify location of jamf binary.
jamf_binary=`/usr/bin/which jamf`

if [[ "$jamf_binary" == "" ]] && [[ -e "/usr/sbin/jamf" ]] && [[ ! -e "/usr/local/bin/jamf" ]]; then
    jamf_binary="/usr/sbin/jamf"
elif [[ "$jamf_binary" == "" ]] && [[ ! -e "/usr/sbin/jamf" ]] && [[ -e "/usr/local/bin/jamf" ]]; then
    jamf_binary="/usr/local/bin/jamf"
elif [[ "$jamf_binary" == "" ]] && [[ -e "/usr/sbin/jamf" ]] && [[ -e "/usr/local/bin/jamf" ]]; then
    jamf_binary="/usr/local/bin/jamf"
fi

ScriptLogging "JAMF Binary is $jamf_binary"
}

# Create the User Account
CreateLAPSaccount (){
    ScriptLogging "Creating LAPS Account..."
    echo "Creating LAPS Account..."
    if [ "$hideLAPSuser" == "0" ]; then
        $jamf_binary createAccount -username $LAPSuser -realname $LAPSuserDisplay -password $newPass -suppressSetupAssistant -admin
    elif [ "$hideLAPSuser" == "1" ]; then
        $jamf_binary createAccount -username $LAPSuser -realname $LAPSuserDisplay -password $newPass -suppressSetupAssistant -admin
        dscl . -create /Users/$LAPSuser IsHidden 1
    fi
    ScriptLogging "LAPS Account Created..."
    echo "LAPS Account Created..."
}

# Update the LAPS Extention Attribute
UpdateAPI (){
    ScriptLogging "Recording new password for $LAPSuser into LAPS."
    /usr/bin/curl -s -f -u ${apiUser}:${apiPass} -X PUT -H "Content-Type: text/xml" -d "${xmlString}" "${apiURL}/JSSResource/computers/udid/$udid"
}

CheckBinary
UpdateAPI
CreateLAPSaccount
UpdateAPI

ScriptLogging "======== LAPS Account Creation Complete ========"
echo "LAPS Account Creation Finished."

# Run LAPS Password Randomization
$jamf_binary policy -event $LAPSrunEvent

exit 0
