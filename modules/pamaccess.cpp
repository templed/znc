/*
 * Copyright (C) 2015 Douglas Temple <douglas@dtemple.info>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @class CPAMAccessMod
 * @author Douglas Temple <douglas@dtemple.info>
 * @brief Use PAM's pam_access to allow/deny users.
 */

#include <znc/znc.h>
#include <znc/User.h>

#include <security/pam_appl.h>

#define MESSAGE "You do not have access to this service. Contact your administrator if\n you believe this to be an error."

class CPAMAccessMod : public CModule {
public:
	MODCONSTRUCTOR(CPAMAccessMod) {
	}

	virtual ~CPAMAccessMod() {
	}

	void OnModCommand(const CString& sCommand) {
		if (m_pUser->IsAdmin()) {
			HandleCommand(sCommand);
		} else {
			PutModule("Access denied");
		}
	}

//	virtual bool OnLoad(const CString& sArgs, CString& sMessage) {
//		return true;
//	}

	virtual EModRet OnLoginAttempt(std::shared_ptr<CAuthBase> Auth) {
		const CString& sUsername = Auth->GetUsername();
		const CString& sPassword = Auth->GetPassword();
		static struct pam_conv conv = { NULL, NULL };
		pam_handle_t *pamh = NULL;
		int pamret;
		int accessret = PAM_AUTH_ERR;

		// Initialize the PAM transaction		
		pamret = pam_start("znc",sUsername.c_str(),&conv,&pamh);
		if (pamret == PAM_SUCCESS) {
			// Check if the user is allowed access via PAM's account context
			accessret = pam_acct_mgmt(pamh, 0);
		}
		else {
			const char *errstr = pam_strerror(pamh,pamret);
			CUtils::PrintError("pamaccess: Error, PAM failure: "+*errstr);
			// If PAM fails, we should fall back to local users, etc., so don't HALT here
			return CONTINUE; 
		}

		if (accessret == PAM_SUCCESS) {
			DEBUG("pamaccess: User " + sUsername + " allowed access");
		}
		else if (accessret == PAM_PERM_DENIED) {
			DEBUG("pamaccess: User " + sUsername + " denied access.");
			// User is not allowed, so stop any attempts to log in
			Auth->RefuseLogin(MESSAGE);
			return HALT;
		}
		else if (accessret == PAM_ACCT_EXPIRED) {
			DEBUG("pamaccess: User " + sUsername + " denied access.");
			// User's account has expired, so stop any attempts to log in
			Auth->RefuseLogin(MESSAGE);
			return HALT;
		}
		else {
			// Every other option, including if the account doesn't exist in PAM
			const char *errstr = pam_strerror(pamh,accessret);
			CUtils::PrintError("pamaccess: Error, PAM failure: " + *errstr);
			DEBUG("pamaccess: Warning: " + sUsername + " caused PAM to reply: " + *errstr);
		}

		return CONTINUE;
	}

};

template<> void TModInfo<CPAMAccessMod>(CModInfo& Info) {
//	Info.SetWikiPage("pamaccess");
	Info.SetHasArgs(false);
}

GLOBALMODULEDEFS(CPAMAccessMod, "Allow users to be granted or denied access by pam_access mod using the znc service.")
