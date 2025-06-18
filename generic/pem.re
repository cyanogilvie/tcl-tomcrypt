#include "tomcryptInt.h"

int pem_load_first_key(Tcl_Interp* interp, Tcl_Obj* obj, uint8_t** der_buf, unsigned long* der_len, int* is_private_key) //<<<
{
	int				code = TCL_OK;
	const uint8_t*	str = (const uint8_t*)Tcl_GetString(obj);
	const uint8_t*	cur = str;
	/*!stags:re2c format = "const uint8_t* @@{tag}; "; */

	// Aims for RFC 7468 compliance

	*der_buf = NULL;

	/*!rules:re2c:common
		re2c:define:YYCTYPE		= "uint8_t";
		re2c:define:YYCURSOR	= cur;
		re2c:yyfill:enable		= 0;
		re2c:flags:tags			= 1;
		re2c:define:YYSTAGP		= "@{tag} = cur;";
		re2c:define:YYSTAGN		= "@{tag} = NULL;";

		end		= [\x00];
		eol		= [\n\r] | "\r\n";
		WSP		= [ \t];
		W		= WSP | [\n\r\x0b\x0c];
		eolWSP	= WSP | [\n\r];
	*/

	for (;;) {
		const uint8_t		*s1, *e1, *s2, *e2, *b64_start, *b64_end;
		const uint8_t*		YYMARKER;
		/*!re2c
			!use:common;

			label
				= "PUBLIC KEY"
				| "RSA PUBLIC KEY"
				| "RSA PRIVATE KEY"
				;
			preeb		= "-----BEGIN " @s1 label @e1 "-----";
			posteb		= "-----END " @s2 label @e2 "-----";
			b64char 	= [A-Za-z0-9+/];
			b64line		= b64char+ WSP* eol;
			b64final	= b64char* ("=" WSP* eol "=" | "==")? WSP* eol;
			b64text		= b64line* b64final;

			end		{ break; }
			eol		{ continue; }
			*		{ goto skip_to_next_line; }

			preeb WSP* eol eolWSP* @b64_start b64text @b64_end posteb WSP* eol?	{
				goto found_pem;
			}
		*/

	skip_to_next_line:
		for (;;) {
			/*!re2c
				!use:common;

				eol		{ break; }
				end		{ goto finally; }
				*		{ continue; }
			*/
		}
		continue;

	found_pem:
		// Check that the start and end labels match
		if (
			e1-s1 != e2-s2 ||
			strncmp((const char*)s1, (const char*)s2, e1-s1) != 0
		) {
			Tcl_SetErrorCode(interp, "TOMCRYPT", "FORMAT", "PEM", NULL);
			THROW_PRINTF_LABEL(finally, code, "PEM labels do not match");
		}

		*is_private_key = strncmp((const char*)s1, "RSA PRIVATE", 11) == 0;

		// Base64 to DER size (over)estimate
		const size_t der_len_estimate = ((b64_end - b64_start) * 3 / 4) + 1;
		*der_len = der_len_estimate;
		*der_buf = (uint8_t*)ckalloc(*der_len);

		const int decode_rc = base64_sane_decode(
			(const char*)b64_start,	b64_end - b64_start,
			*der_buf,				der_len
		);
		if (decode_rc != CRYPT_OK) {
			Tcl_SetErrorCode(interp, "TOMCRYPT", "FORMAT", "BASE64", NULL);
			THROW_PRINTF_LABEL(finally, code, "Invalid base64 content in PEM");
		}
		break;
	}

finally:
	if (code != TCL_OK) {
		if (*der_buf) {
			ckfree(*der_buf);
			*der_buf = NULL;
		}
	}
	return code;
}

//>>>

// vim: ft=c foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4 noexpandtab
