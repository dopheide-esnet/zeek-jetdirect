##! Detect exploit attempt of HP JetDirect printers

@load policy/frameworks/notice

redef signature_files += "cve-2017-2741.sig";

module JetDirect;

export {
	redef enum Notice::Type += {
		Exploit_Attempt
	};
}

function JetDirect::jetdirect_exploit_sig_match(state: signature_state, data: string): bool{
	NOTICE( [$note=JetDirect::Exploit_Attempt,
			$conn=state$conn,
			$suppress_for=5min,
			$msg=fmt("CVE-2017-2741 exploit attempted"),
			$identifier=cat(state$conn$id$orig_h,state$conn$id$resp_h)] );	
	return T;
}
