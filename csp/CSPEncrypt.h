#pragma once

class CSPEncrypt
{
public:
	CSPEncrypt();
	~CSPEncrypt();

private:
	HCRYPTPROV m_hProv;
};
