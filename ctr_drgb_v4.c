#include "ctr_drbg.h"
#include "seed.h"
#include "aria.h"
#include "sha2.h"
//2017-07-20
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

#define DRBG_ALGO_SEED			0x20
#define DRBG_ALGO_ARIA128		0x31
#define DRBG_ALGO_ARIA192		0x32
#define DRBG_ALGO_ARIA256		0x33

//------------------------------------------------
#define ALGO_SEED_OUTLEN_IN_BYTES				16
#define ALGO_ARIA128_OUTLEN_IN_BYTES			16
#define ALGO_ARIA192_OUTLEN_IN_BYTES			16
#define ALGO_ARIA256_OUTLEN_IN_BYTES			16

//------------------------------------------------
#define ALGO_SEED_KEYLEN_IN_BYTES				16
#define ALGO_ARIA128_KEYLEN_IN_BYTES			16
#define ALGO_ARIA192_KEYLEN_IN_BYTES			24
#define ALGO_ARIA256_KEYLEN_IN_BYTES			32

//------------------------------------------------
#define ALGO_SEED_SECURITY_STRENGTH_IN_BYTES	16
#define ALGO_ARIA128_SECURITY_STRENGTH_IN_BYTES	16
#define ALGO_ARIA192_SECURITY_STRENGTH_IN_BYTES	24
#define ALGO_ARIA256_SECURITY_STRENGTH_IN_BYTES	32

//------------------------------------------------
#define ALGO_SEED_SEEDLEN_IN_BYTES				ALGO_SEED_OUTLEN_IN_BYTES + ALGO_SEED_KEYLEN_IN_BYTES
#define ALGO_ARIA128_SEEDLEN_IN_BYTES			ALGO_ARIA128_OUTLEN_IN_BYTES + ALGO_ARIA128_KEYLEN_IN_BYTES
#define ALGO_ARIA192_SEEDLEN_IN_BYTES			ALGO_ARIA192_OUTLEN_IN_BYTES + ALGO_ARIA192_KEYLEN_IN_BYTES
#define ALGO_ARIA256_SEEDLEN_IN_BYTES			ALGO_ARIA256_OUTLEN_IN_BYTES + ALGO_ARIA256_KEYLEN_IN_BYTES

//------------------------------------------------
#define MAX_V_LEN_IN_BYTES						16
#define MAX_Key_LEN_IN_BYTES					32
#define MAX_SEEDLEN_IN_BYTES					ALGO_ARIA256_SEEDLEN_IN_BYTES

//------------------------------------------------
#define MIN_ENTROPY_INPUT_LEN_IN_BYTES			// Depends on SECURITY_STRENGTH of each algorithm

//------------------------------------------------
#define MAX_NUM_INPUT_OF_BYTES_PER_REQUEST		0x10000			// 2^19 bits

//------------------------------------------------
#define MAX_ENTROPY_INPUT_LEN_IN_BYTES			0x100000000		// 2^35 bits
#define MAX_PERSONALIZED_STRING_LEN_IN_BYTES	0x100000000		// 2^35 bits
#define MAX_ADDITIONAL_INPUT_LEN_IN_BYTES		0x100000000		// 2^35 bits
#define NUM_OF_REQUESTS_BETWEEN_RESEEDS			0x1000000000000UL// 2^48 bits

#define STATE_INITIALIZED_FLAG					0xFE12DC34

//------------------------------------------------
#define NON_DERIVATION_FUNCTION					0x00
#define USE_DERIVATION_FUNCTION					0xFF

#define NO_HEAP_BUF_SIZE						3072


	/*!
	 * \brief
	 * CTR DRBG 구현을 위한 내부 변수 구조체 (STATE)
	 */
	/*typedef struct ctr_drbg_state{
		unsigned char	algo;
		unsigned char	V[MAX_V_LEN_IN_BYTES];
		int				Vlen;
		unsigned char	Key[MAX_Key_LEN_IN_BYTES];
		int				Keylen;
		int				seedlen;
		unsigned long long reseed_counter;
		int				security_strength;		
		int				initialized_flag;		  // If initialized_flag = STATE_INITIALIZED_FLAG, state is already initialized.
		unsigned char	derivation_function_flag; // 0x00 : non-df ,  0xFF : use df
	} CTR_DRBG_STATE;*/

# define octet_to_int(os) (((unsigned int)(os)[0] << 24) ^ ((unsigned int)(os)[1] << 16) ^ ((unsigned int)(os)[2] <<  8) ^ ((unsigned int)(os)[3]))
# define int_to_octet(os, i) { (os)[0] = (unsigned char)((i) >> 24); (os)[1] = (unsigned char)((i) >> 16); (os)[2] = (unsigned char)((i) >>  8); (os)[3] = (unsigned char)(i); }

static void ctr_increase(unsigned char *counter) {

	unsigned int c_byte;

	c_byte = octet_to_int(counter + 12);
	c_byte++;
	c_byte &= 0xFFFFFFFF;
	int_to_octet(counter + 12, c_byte);
	if (c_byte)
		return;

	c_byte = octet_to_int(counter +  8);
	c_byte++;	
	c_byte &= 0xFFFFFFFF;
	int_to_octet(counter +  8, c_byte);

	if (c_byte)
		return;

	c_byte = octet_to_int(counter +  4);
	c_byte++;
	c_byte &= 0xFFFFFFFF;
	int_to_octet(counter +  4, c_byte);

	if (c_byte)
		return;


	c_byte = octet_to_int(counter +  0);
	c_byte++;
	c_byte &= 0xFFFFFFFF;
	int_to_octet(counter +  0, c_byte);
}

void BCC(char algo,
			  unsigned char* K,
			  unsigned char* data, int datalen,
			  unsigned char* output_block, int outlen)
{
	SEED_KEY seedkey;
	ARIA_KEY ariakey;
	int n = datalen/outlen;
	int i,j;
	unsigned char inputblock[MAX_V_LEN_IN_BYTES];
	memset(inputblock,0x00,MAX_V_LEN_IN_BYTES);
	memset(output_block,0x00,outlen);
	
	
	switch(algo){
		case DRBG_ALGO_SEED:
			SEED_init(K,&seedkey);

			for(j=1; j <= n; j++)
			{				
				for(i=0; i<outlen; i++)
				{
					inputblock[i] = output_block[i] ^ data[i];
				}
				SEED_encrypt_block(inputblock,output_block,&seedkey);				
				data		 += SEED_BLOCK_SIZE;				
			}
			break;
		case DRBG_ALGO_ARIA128:
			ARIA_encrypt_init(K,128,&ariakey);

			for(j=1; j <= n; j++)
			{
				for(i=0; i<outlen; i++)
				{
					inputblock[i] = output_block[i] ^ data[i];
				}
				ARIA_process_block(inputblock,output_block,&ariakey, 1);				
				data		 += ARIA_BLOCK_SIZE;
			}
			break;
		case DRBG_ALGO_ARIA192:
			ARIA_encrypt_init(K,192,&ariakey);

			for(j=1; j <= n; j++)
			{
				for(i=0; i<outlen; i++)
				{
					inputblock[i] = output_block[i] ^ data[i];
				}
				ARIA_process_block(inputblock,output_block,&ariakey, 1);				
				data		 += ARIA_BLOCK_SIZE;
			}
			break;
		case DRBG_ALGO_ARIA256:
			ARIA_encrypt_init(K,256,&ariakey);

			for(j=1; j <= n; j++)
			{
				for(i=0; i<outlen; i++)
				{
					inputblock[i] = output_block[i] ^ data[i];
				}
				ARIA_process_block(inputblock,output_block,&ariakey, 1);				
				data		 += ARIA_BLOCK_SIZE;
			}
			break;
	}

	memset(&ariakey,0x00,sizeof(ARIA_KEY));
	memset(&seedkey,0x00,sizeof(SEED_KEY));
	memset(inputblock,0x00,MAX_V_LEN_IN_BYTES);
}

int Blockcipher_df(char algo,
						unsigned char *input_string, int input_str_len,
						unsigned char *output, int outlen)
{
#define MAX_NUM_OF_BYTES_TO_RETURN 64
#define BLOCK_SIZE MAX_V_LEN_IN_BYTES
#define SIZE_INT	4

	int retcode = 0;
	int i = 0;
	int L = input_str_len;
	int N = outlen;
	unsigned char X [MAX_NUM_OF_BYTES_TO_RETURN];
	unsigned char K [ALGO_ARIA256_KEYLEN_IN_BYTES];
	int KLen;
	unsigned char IV[BLOCK_SIZE];
	unsigned char block[BLOCK_SIZE];
	int j;
	unsigned char S[NO_HEAP_BUF_SIZE] = {0x00, };
	int SLen = 0;
	unsigned char temp[NO_HEAP_BUF_SIZE] = {0x00, };
	unsigned char iv_s[NO_HEAP_BUF_SIZE] = {0x00, };
	int iv_s_len = 0;
	int templen = 0;
	unsigned char *ptr;
	SEED_KEY seedkey;
	ARIA_KEY ariakey;

	if(outlen > MAX_NUM_OF_BYTES_TO_RETURN)
	{
		goto FREE_AND_EXIT;
	}

	// form S = L||N||input_string||0x80	
	SLen = 8 + input_str_len + 1;
	if((SLen % SEED_BLOCK_SIZE) != 0)
		SLen += (SEED_BLOCK_SIZE - (SLen % SEED_BLOCK_SIZE));
	
	memset(S,0x00,SLen);
	int_to_octet(S    , L);
	int_to_octet(S + SIZE_INT, N);
	memcpy(S + SIZE_INT + SIZE_INT, input_string, input_str_len);
	S[SIZE_INT+SIZE_INT+input_str_len] = 0x80;
	
	for(j=0; j<ALGO_ARIA256_KEYLEN_IN_BYTES; j++)
		K[j] = j;

	KLen = (algo == DRBG_ALGO_SEED) ? ALGO_SEED_KEYLEN_IN_BYTES : (algo == DRBG_ALGO_ARIA128) ? ALGO_ARIA128_KEYLEN_IN_BYTES : (algo == DRBG_ALGO_ARIA192) ? ALGO_ARIA192_KEYLEN_IN_BYTES : ALGO_ARIA256_KEYLEN_IN_BYTES;

	templen = (KLen+outlen) + (BLOCK_SIZE - ((KLen+outlen) % BLOCK_SIZE));	
	ptr = temp;
	iv_s_len = SLen + BLOCK_SIZE;
	i = 0;
	templen = 0;
	while(templen < KLen + outlen){		
		int_to_octet(IV,i);
		memset(IV+SIZE_INT,0x00,BLOCK_SIZE-SIZE_INT);
		memcpy(iv_s,IV,BLOCK_SIZE);
		memcpy(iv_s + BLOCK_SIZE,S,SLen);
		
		BCC(algo,K,iv_s,iv_s_len,block,BLOCK_SIZE);
		memcpy(ptr,block,BLOCK_SIZE);
		ptr += BLOCK_SIZE;
		templen += BLOCK_SIZE;
		i++;
	}

	memcpy(K,temp,KLen);
	memcpy(X,temp+KLen,outlen);

	memset(temp, 0x00, NO_HEAP_BUF_SIZE);
	ptr = temp;
	templen = 0;	

	switch(algo)
	{
	case DRBG_ALGO_SEED:

		SEED_init(K,&seedkey);
		while(templen < outlen){
			SEED_encrypt_block(X,X,&seedkey);
			memcpy(ptr,X,BLOCK_SIZE);
			ptr += BLOCK_SIZE;
			templen += BLOCK_SIZE;					
		}
		break;	
	case DRBG_ALGO_ARIA128:
		ARIA_encrypt_init(K,ARIA128,&ariakey);			
		while(templen < outlen){
			ARIA_process_block(X,X,&ariakey, 1);
			memcpy(ptr,X,BLOCK_SIZE);
			ptr += BLOCK_SIZE;
			templen += BLOCK_SIZE;
		}
		break;	
	case DRBG_ALGO_ARIA192:
		ARIA_encrypt_init(K,ARIA192,&ariakey);			
		while(templen < outlen){
			ARIA_process_block(X,X,&ariakey, 1);
			memcpy(ptr,X,BLOCK_SIZE);
			ptr += BLOCK_SIZE;
			templen += BLOCK_SIZE;
		}
		break;	
	case DRBG_ALGO_ARIA256:
		ARIA_encrypt_init(K,ARIA256,&ariakey);			
		while(templen < outlen){
			ARIA_process_block(X,X,&ariakey, 1);
			memcpy(ptr,X,BLOCK_SIZE);
			ptr += BLOCK_SIZE;
			templen += BLOCK_SIZE;
		}
		break;	
	}

	memcpy(output,temp,outlen);

	retcode = 1;
FREE_AND_EXIT:
	memset(&ariakey,0x00,sizeof(ARIA_KEY));
	memset(&seedkey,0x00,sizeof(SEED_KEY));
	memset(S, 0x00, NO_HEAP_BUF_SIZE);
	memset(temp, 0x00, NO_HEAP_BUF_SIZE);
	memset(iv_s, 0x00, NO_HEAP_BUF_SIZE);
	memset(X,0x00,MAX_NUM_OF_BYTES_TO_RETURN);
	memset(K,0x00,ALGO_ARIA256_KEYLEN_IN_BYTES);
	memset(IV,0x00,BLOCK_SIZE);
	memset(block,0x00,BLOCK_SIZE);	
	return retcode;	
}

static int CTR_DRBG_Update (unsigned char* provided_data, CTR_DRBG_STATE *state)
{
	unsigned char temp[MAX_SEEDLEN_IN_BYTES];
	int templen = 0;
	unsigned char* ptr;
	int i;
	SEED_KEY seedkey;
	ARIA_KEY ariakey;
	
	if( !provided_data || (state->seedlen <= 0) )
	{
		return 0;
	}
	
	ptr = temp;
	
	switch (state->algo){
		case DRBG_ALGO_SEED:
			SEED_init(state->Key,&seedkey);
			while(templen < state->seedlen)
			{
				ctr_increase(state->V);	
				SEED_encrypt_block(state->V,ptr,&seedkey);
				ptr += SEED_BLOCK_SIZE;				
				templen += SEED_BLOCK_SIZE;
			}
			memset(&seedkey,0x00,sizeof(SEED_KEY));
			break;
		case DRBG_ALGO_ARIA128:
			ARIA_encrypt_init(state->Key,ARIA128,&ariakey);
			while(templen < state->seedlen)
			{
				ctr_increase(state->V);								
				ARIA_process_block(state->V,ptr,&ariakey, 1);
				ptr += ARIA_BLOCK_SIZE;				
				templen += ARIA_BLOCK_SIZE;
			}
			memset(&ariakey,0x00,sizeof(ARIA_KEY));
			break;	
		case DRBG_ALGO_ARIA192:
			ARIA_encrypt_init(state->Key,ARIA192,&ariakey);
			while(templen < state->seedlen)
			{
				ctr_increase(state->V);								
				ARIA_process_block(state->V,ptr,&ariakey, 1);
				ptr += ARIA_BLOCK_SIZE;				
				templen += ARIA_BLOCK_SIZE;
			}
			memset(&ariakey,0x00,sizeof(ARIA_KEY));
			break;	
		case DRBG_ALGO_ARIA256:
			ARIA_encrypt_init(state->Key,ARIA256,&ariakey);
			while(templen < state->seedlen)
			{
				ctr_increase(state->V);								
				ARIA_process_block(state->V,ptr,&ariakey, 1);
				ptr += ARIA_BLOCK_SIZE;				
				templen += ARIA_BLOCK_SIZE;
			}
			memset(&ariakey,0x00,sizeof(ARIA_KEY));
			break;	
	}

	for(i = 0; i<state->seedlen; i++)
		temp[i] ^= provided_data[i];
	
	memcpy(state->Key,temp,state->Keylen);
	ptr = temp;
	memcpy(state->V,ptr + state->seedlen - (state->Vlen), state->Vlen);

	memset(temp,0x00,state->seedlen);

	return 1;
}

int CTR_DRBG_Instantiate(CTR_DRBG_STATE *state,
							  unsigned char  algo,
							  unsigned char* entropy_input, int entropylen,
							  unsigned char* nonce, int noncelen,
							  unsigned char* personalization_string, int stringlen,
							  unsigned char derivation_function_flag)
{
	// ----------------------------------
	// 핵심보안매개변수 초기화 대상
	// ----------------------------------
	unsigned char	seed_material[MAX_SEEDLEN_IN_BYTES];
	unsigned char	seed_material_in[NO_HEAP_BUF_SIZE] = {0x00, };
	unsigned char*	ptr				 = NULL;
	// ----------------------------------
	int				seed_material_len = 0;
	int				retcode = 0;
	
	if( (*point_to_OPmode == NotDefined) || ((*point_to_ModuleAvailable & CTRDRBG_Enabled) != CTRDRBG_Enabled) )
		return -3;
	
	if( !entropy_input || !state || (entropylen < 0) || (noncelen < 0) || (stringlen < 0) )
	{
		return -4;
	}

	if(derivation_function_flag == USE_DERIVATION_FUNCTION)
	{
		state->derivation_function_flag = USE_DERIVATION_FUNCTION;
	}
	else
	{
		state->derivation_function_flag = NON_DERIVATION_FUNCTION;
	}

	switch(algo)
	{

		case DRBG_ALGO_SEED:
			if(derivation_function_flag == USE_DERIVATION_FUNCTION)
			{
				if(entropylen < ALGO_SEED_SECURITY_STRENGTH_IN_BYTES )
					return -4;
			}
			else
			{
				if(entropylen < ALGO_SEED_SEEDLEN_IN_BYTES )
					return -4;
			}

			if( nonce && noncelen < ALGO_SEED_SECURITY_STRENGTH_IN_BYTES/2)
				return -4;

			state->seedlen = ALGO_SEED_SEEDLEN_IN_BYTES;
			state->Keylen = ALGO_SEED_KEYLEN_IN_BYTES;
			state->Vlen = ALGO_SEED_OUTLEN_IN_BYTES;			
			break;

		//--------------------------------------------------------------
		case DRBG_ALGO_ARIA128:
			if(derivation_function_flag == USE_DERIVATION_FUNCTION)
			{
				if(entropylen < ALGO_ARIA128_SECURITY_STRENGTH_IN_BYTES )
					return -4;
			}
			else
			{
				if(entropylen < ALGO_ARIA128_SEEDLEN_IN_BYTES )
					return -4;
			}

			if( nonce && noncelen < ALGO_ARIA128_SECURITY_STRENGTH_IN_BYTES/2)
				return -4;

			state->seedlen = ALGO_ARIA128_SEEDLEN_IN_BYTES;
			state->Keylen = ALGO_ARIA128_KEYLEN_IN_BYTES;
			state->Vlen = ALGO_ARIA128_OUTLEN_IN_BYTES;
			break;
		
		//--------------------------------------------------------------
		case DRBG_ALGO_ARIA192:	
			if(derivation_function_flag == USE_DERIVATION_FUNCTION)
			{
				if(entropylen < ALGO_ARIA192_SECURITY_STRENGTH_IN_BYTES )
					return -4;
			}
			else
			{
				if(entropylen < ALGO_ARIA192_SEEDLEN_IN_BYTES )
					return -4;
			}

			if( nonce && noncelen < ALGO_ARIA192_SECURITY_STRENGTH_IN_BYTES/2)
				return -4;

			state->seedlen = ALGO_ARIA192_SEEDLEN_IN_BYTES;
			state->Keylen = ALGO_ARIA192_KEYLEN_IN_BYTES;
			state->Vlen = ALGO_ARIA192_OUTLEN_IN_BYTES;
			break;

		//--------------------------------------------------------------
		case DRBG_ALGO_ARIA256:	
			if(derivation_function_flag == USE_DERIVATION_FUNCTION)
			{
				if(entropylen < ALGO_ARIA256_SECURITY_STRENGTH_IN_BYTES )
					return -4;
			}
			else
			{
				if(entropylen < ALGO_ARIA256_SEEDLEN_IN_BYTES )
					return -4;
			}

			if( nonce && noncelen < ALGO_ARIA256_SECURITY_STRENGTH_IN_BYTES/2)
				return -4;

			state->seedlen = ALGO_ARIA256_SEEDLEN_IN_BYTES;
			state->Keylen = ALGO_ARIA256_KEYLEN_IN_BYTES;
			state->Vlen = ALGO_ARIA256_OUTLEN_IN_BYTES;
			break;

		default:
			return -4;
	}

	state->algo = algo;

	if(state->derivation_function_flag == USE_DERIVATION_FUNCTION)
	{
		memset(seed_material, 0x00, MAX_SEEDLEN_IN_BYTES);
		seed_material_len = entropylen;
		if( nonce && noncelen > 0)
		 	seed_material_len += (noncelen);
		 	
		if(personalization_string && stringlen > 0)
		 	seed_material_len += (stringlen);

		ptr = seed_material_in;
		memcpy(ptr, entropy_input, entropylen);
		if( nonce && noncelen > 0)
		{
			ptr += entropylen;
			memcpy(ptr, nonce, noncelen);			
		}
		
		if(personalization_string && stringlen > 0)
		{
			ptr += noncelen;
			memcpy(ptr, personalization_string, stringlen);		
		}

		if(!Blockcipher_df(algo,seed_material_in,seed_material_len,seed_material,state->seedlen))
		{
			goto FREE_AND_EXIT;
		}
	}
	else
	{
		int i;

		memcpy(seed_material, entropy_input, entropylen);
		if(personalization_string != NULL && stringlen > 0) {
			for(i = 0; i < stringlen; i++)
				seed_material[i] ^= personalization_string[i];
		}
	}

	memset(state->Key, 0x00, MAX_Key_LEN_IN_BYTES);
	memset(state->V, 0x00, MAX_V_LEN_IN_BYTES);

	if(!CTR_DRBG_Update(seed_material,state))
	{
		goto FREE_AND_EXIT;
	}

	state->reseed_counter = 1;

	retcode = 1;
	state->initialized_flag = STATE_INITIALIZED_FLAG;

FREE_AND_EXIT:
	// ----------------------------------
	// 핵심보안매개변수 초기화
	// ----------------------------------
	memset(seed_material_in, 0x00, NO_HEAP_BUF_SIZE);
	memset(seed_material,0x00,MAX_SEEDLEN_IN_BYTES);
	// ----------------------------------
	return retcode;
}

int CTR_DRBG_Reseed(CTR_DRBG_STATE *state,
					     unsigned char* entropy_input, int entropylen,
						 unsigned char* additional_input, int addlen
						 )
{
	// ----------------------------------
	// 핵심보안매개변수 초기화 대상
	// ----------------------------------
	unsigned char	seed_material[MAX_SEEDLEN_IN_BYTES];
	unsigned char	seed_material_in[NO_HEAP_BUF_SIZE] = {0x00, };
	unsigned char*	ptr			 = NULL;
	// ----------------------------------
	int				seed_material_len = 0;
	int				retcode = 0;
	
	if( (*point_to_OPmode == NotDefined) || ((*point_to_ModuleAvailable & CTRDRBG_Enabled) != CTRDRBG_Enabled) )
		return -3;
		
	if( !state || !entropy_input || (entropylen < 0) || (additional_input < 0) )
		return -4;

	if(addlen > state->seedlen)
	{
		addlen = state->seedlen;
	}

	if(state->initialized_flag != STATE_INITIALIZED_FLAG)
	{
		return -5; // CTR_DRBG_Instantiate(...) required
	}

	switch(state->algo)
	{
		
		//--------------------------------------------------------------
		case DRBG_ALGO_SEED:
			if(entropylen < ALGO_SEED_SECURITY_STRENGTH_IN_BYTES)
				return -4;			
			break;

		//--------------------------------------------------------------
		case DRBG_ALGO_ARIA128:
			if(entropylen < ALGO_ARIA128_SECURITY_STRENGTH_IN_BYTES)
				return -4;
			break;
		
		//--------------------------------------------------------------
		case DRBG_ALGO_ARIA192:	
			if(entropylen < ALGO_ARIA192_SECURITY_STRENGTH_IN_BYTES)
				return -4;
			break;

		//--------------------------------------------------------------
		case DRBG_ALGO_ARIA256:	
			if(entropylen < ALGO_ARIA256_SECURITY_STRENGTH_IN_BYTES)
				return -4;
			break;

		default:
			return -4; // No Such Algorithm
	}

	if(state->derivation_function_flag == USE_DERIVATION_FUNCTION)
	{
		memset(seed_material,0x00,MAX_SEEDLEN_IN_BYTES);
		seed_material_len = entropylen;
		if(addlen > 0)
			seed_material_len += (addlen);
			
		ptr = seed_material_in;
		memcpy(ptr, entropy_input, entropylen);
		if(addlen > 0)
		{
			ptr += entropylen;
			memcpy(ptr, additional_input, addlen);		
		}

		if(!Blockcipher_df(state->algo,seed_material_in,seed_material_len,seed_material,state->seedlen))
		{
			goto FREE_AND_EXIT;
		}
	}
	else
	{
		int i;

		memcpy(seed_material,entropy_input,entropylen);
		if(additional_input != NULL && addlen > 0) {
			for(i = 0; i < addlen; i++) {
				seed_material[i] ^= additional_input[i];
			}
		}
	}
	
	if(!CTR_DRBG_Update(seed_material,state))
	{
		goto FREE_AND_EXIT;
	}

	state->reseed_counter = 1;
	
	retcode = 1;

FREE_AND_EXIT:
	// ----------------------------------
	// 핵심보안매개변수 초기화
	// ----------------------------------
	memset(seed_material_in, 0x00, NO_HEAP_BUF_SIZE);
	memset(seed_material,0x00,MAX_SEEDLEN_IN_BYTES);
	// ----------------------------------
	return retcode;
}

int CTR_DRBG_Generate(CTR_DRBG_STATE *state,
						   unsigned char* output, int requested_num_of_bits,
						   unsigned char* addtional_input, int addlen	
						   )
{
	SEED_KEY seed_key;
	ARIA_KEY aria_key;
	unsigned char addtional_input_for_seed[MAX_SEEDLEN_IN_BYTES];
	int request_num_of_bytes;
	
	int retcode = 0;
	unsigned char temp[NO_HEAP_BUF_SIZE] = {0x00, };
	unsigned char* ptr = NULL;
	int templen = 0;
	
	if( (*point_to_OPmode == NotDefined) || ((*point_to_ModuleAvailable & CTRDRBG_Enabled) != CTRDRBG_Enabled) )
		return -3;
		
	if( !state || !output || (requested_num_of_bits <= 0) || (addlen < 0) )
		return -4;
	
	if(addlen > state->seedlen)
	{
		addlen = state->seedlen;
	}

	request_num_of_bytes = requested_num_of_bits / 8 + ((requested_num_of_bits % 8) != 0 ? 1 : 0);

	if(state->reseed_counter > NUM_OF_REQUESTS_BETWEEN_RESEEDS)
	{
		return -5; // Reseed Required.
	}
	
	if(addtional_input != NULL && addlen > 0) {
		if(state->derivation_function_flag == USE_DERIVATION_FUNCTION)
		{
			if(!Blockcipher_df(state->algo,addtional_input,addlen,addtional_input_for_seed,state->seedlen))
			{
				memset(addtional_input_for_seed,0x00,MAX_SEEDLEN_IN_BYTES);
				return -5;
			}

			if(!CTR_DRBG_Update(addtional_input_for_seed,state))
			{
				memset(addtional_input_for_seed,0x00,MAX_SEEDLEN_IN_BYTES);
				return -5;
			}
		}
		else
		{
			memset(addtional_input_for_seed,0x00,MAX_SEEDLEN_IN_BYTES);
			memcpy(addtional_input_for_seed, addtional_input, addlen);
			

			if(!CTR_DRBG_Update(addtional_input_for_seed,state))
			{
				memset(addtional_input_for_seed,0x00,MAX_SEEDLEN_IN_BYTES);
				return -5;
			}
		}
	}
		
	ptr = temp;
	templen = 0;

	switch(state->algo)
	{
	case DRBG_ALGO_SEED:
		SEED_init(state->Key, &seed_key);
		while(templen < request_num_of_bytes)
		{
			ctr_increase(state->V);
			SEED_encrypt_block(state->V,ptr,&seed_key);
			ptr += ALGO_SEED_OUTLEN_IN_BYTES;
			templen += ALGO_SEED_OUTLEN_IN_BYTES;
		}
		memset(&seed_key,0x00,sizeof(SEED_KEY));
		break;
	case DRBG_ALGO_ARIA128:
		ARIA_encrypt_init(state->Key, 128 ,&aria_key);
		while(templen < request_num_of_bytes)
		{
			ctr_increase(state->V);
			ARIA_process_block(state->V,ptr,&aria_key, 1);
			ptr += ALGO_ARIA128_OUTLEN_IN_BYTES;
			templen += ALGO_ARIA128_OUTLEN_IN_BYTES;
		}
		memset(&aria_key,0x00,sizeof(ARIA_KEY));
		break;
	case DRBG_ALGO_ARIA192:
		ARIA_encrypt_init(state->Key, 192 ,&aria_key);
		while(templen < request_num_of_bytes)
		{
			ctr_increase(state->V);
			ARIA_process_block(state->V,ptr,&aria_key, 1);
			ptr += ALGO_ARIA192_OUTLEN_IN_BYTES;
			templen += ALGO_ARIA192_OUTLEN_IN_BYTES;
		}
		memset(&aria_key,0x00,sizeof(ARIA_KEY));
		break;
	case DRBG_ALGO_ARIA256:
		ARIA_encrypt_init(state->Key, 256 ,&aria_key);
		while(templen < request_num_of_bytes)
		{
			ctr_increase(state->V);
			ARIA_process_block(state->V,ptr,&aria_key, 1);
			ptr += ALGO_ARIA256_OUTLEN_IN_BYTES;
			templen += ALGO_ARIA256_OUTLEN_IN_BYTES;
		}
		memset(&aria_key,0x00,sizeof(ARIA_KEY));
		break;
	}
	
	memcpy(output,temp,request_num_of_bytes);
	if(requested_num_of_bits % 8 != 0)
		output[request_num_of_bytes-1] = temp[request_num_of_bytes-1] & (0x000000FF&(0xFF << (8-(requested_num_of_bits%8))));

	if(!CTR_DRBG_Update(addtional_input_for_seed,state))
	{
		goto FREE_AND_EXIT;
	}

	(state->reseed_counter)++;

	retcode = 1;
FREE_AND_EXIT:
	memset(temp, 0x00, NO_HEAP_BUF_SIZE);
	memset(addtional_input_for_seed,0x00,MAX_SEEDLEN_IN_BYTES);	
	
	return retcode;
}

int CTR_DRBG_clear(CTR_DRBG_STATE *state)
{
	// 사용자에게 위임한 핵심보안매개변수 초기화를 위한 함수
	
	if( (*point_to_OPmode == NotDefined) || ((*point_to_ModuleAvailable & CTRDRBG_Enabled) != CTRDRBG_Enabled) )
		return -3;
		
	if( !state )
		return -4;
	
	// ----------------------------------
	// 핵심보안매개변수 초기화 대상
	// ----------------------------------
	memset(state, 0x00, sizeof(CTR_DRBG_STATE));
	// ----------------------------------

	return 1;
}

#define ENT_LEN 128

#ifdef _MicroC_OS_MOD_
static int genEntropy_inner(unsigned char *buf, int len)
{
	SHA256_INFO sha;
	unsigned char input[16];
	unsigned char output[32];

	unsigned int clk, time;
	int iteration, limit;
	int loc;

	loc=0;

	while(len > 0)
	{
		SHA256_init(&sha);
		
		time = OSTimeGet();
		if( (time & 0x01) == 0x01 ) // odd number
		{
			 clk   = BSP_CPU_ClkGet();
			 SHA256_update(&sha, (unsigned char *)&clk, 4);
		}
		SHA256_update(&sha, (unsigned char *)&time, 1);
		
		// get adc value to input
		GetADC(input);
		SHA256_update(&sha, input, 16);
		SHA256_final(&sha, output);
		
		limit = input[time % 16];
		
		for(iteration = 0; iteration < limit; iteration++)
		{
			 SHA256_init(&sha);
			 SHA256_update(&sha, output, 32);
			 SHA256_final(&sha, output);
		}   
		
		if(len >= 32)
		{
			 memcpy(buf + (loc * 32), output, 32);
			 len = len - 32;
				loc++;
		}
		else
		{
			 memcpy(buf + (loc * 32), output, len);
			 len = 0;
		}
	}
	
	SHA256_clear(&sha);
	
	return 1;
}
#else

static void String2Hexarray(char* hstring, unsigned char* harray, int* hsize)
{
   unsigned char value, temp;
   int i=0,j=0,len=strlen(hstring);
   
   while(i<len) {
      temp = *(hstring+i);
      if( ('0' <= temp) && (temp <= '9') ) temp = temp - '0';
      else if( ('a' <= temp) && (temp <= 'f') ) temp = temp - 'a' + 0xA;
      else if( ('A' <= temp) && (temp <= 'F') ) temp = temp - 'A' + 0xA;
      else break;
                  
      if(i%2 == 0) value = temp<<4;
      else {
         value |= temp;
         *(harray+j) = value;
         j++;
      }
      i++;
   }

   *hsize = j;

   return;
}

static int genEntropy_inner(unsigned char *buf, int len)

{

	FILE *fp;

#ifdef KCMVP_APPROVED

#endif
	unsigned char* temp_buf[1024*16];
	char* str_buf[1024*5];
	unsigned char* ptr = temp_buf;
	int length;

	struct timeval kcmvp_time;
	int i;
	//==============================urandom======================
	fp = fopen("/dev/urandom", "r");
	if(!fp){
		printf("!fp error!\n");
		return 0;
	}
	if( !fread(ptr, 1 ,30, fp)){
		printf("!fread urandom error!\n");
	}

	fclose(fp);

	ptr += 30;

	//==============================uuid========================
	fp = popen("sed \"s/-//g\" /proc/sys/kernel/random/uuid","r");
	if(!fp){
		printf("!fp error!\n");
		return 0;
	}

	if(!fgets(str_buf,1024,fp)){
		printf("!fread uuid error!\n");
	}
	String2Hexarray(str_buf, ptr, &length);

	pclose(fp);

	ptr +=length;

	//=============================jiffies=======================
	//fp3 = popen("cat /proc/timer_list | grep \"jiffies:\"","r");
	fp = popen("cat /proc/timer_list | grep \"jiffies:\" | grep -o '[0-9]*' | head -c 11","r");
	if(!fp){
		printf("!fp error!\n");
		return 0;
	}
	*(str_buf+12)='\0';
	if(!fgets(str_buf,1024,fp)){
		printf("!fread jiffies error!\n");
	}
	
	String2Hexarray(str_buf,ptr,&length);
	ptr[length]='\0';

	printf("\n");

	pclose(fp);
	ptr +=length;
	//============================uptime=========================
	fp = popen("cat /proc/uptime","r");
	if(!fp){
		printf("!fp error!\n");
		return 0;
	}
	if(!fgets(str_buf,1024,fp)){
		printf("!fgets uptime error!\n");
	}

	String2Hexarray(str_buf,ptr,&length);
	pclose(fp);
	ptr +=length;

	//============================meminfo========================
	fp = popen("cat /proc/meminfo | grep -o '[0-9]*'" ,"r");
	if(!fp){
		printf("!fp error!\n");
		return 0;
	}

	if(!fread(str_buf,1,1024*5,fp)){
		printf("fgets meminfo error!\n");
	}

	String2Hexarray(str_buf,ptr,&length);
	fclose(fp);
	ptr += length;
	//=======================hash====================
	//printf("temp_buf: %s\n",temp_buf);
	
	sha224(buf,temp_buf,strlen(temp_buf));
	buf[17]='\0';
	return 1;
}

#endif
static int genEntropy(unsigned char *buf, int len)
{
	//------------------------
	// Entropy 생성 테스트용
	//------------------------
	unsigned char ent_test1[ENT_LEN];
	unsigned char ent_test2[ENT_LEN];
	//------------------------
		
	//------------------------
	// Entropy 생성 테스트
	//------------------------
	if( !genEntropy_inner(ent_test1, ENT_LEN) )
		return 0;
		
	if( !genEntropy_inner(ent_test2, ENT_LEN) )
		return 0;
	
	if(!memcmp(ent_test1, ent_test2, ENT_LEN))
	{
		return 0;
	}

	if( !genEntropy_inner(buf, len) )
		return 0;

	return 1;
}

int CTR_DRBG_Random_Gen(unsigned char *output, int request_num_of_bits)
{
	CTR_DRBG_STATE drbg;
	unsigned char ent1[ENT_LEN];
	unsigned char ent2[ENT_LEN];
	unsigned char ent3[ENT_LEN];
	unsigned char ent4[ENT_LEN];
	unsigned char ent5[ENT_LEN];
	unsigned char ent6[ENT_LEN];
	unsigned char ent7[ENT_LEN];
	unsigned char ent8[ENT_LEN];
	unsigned char ent9[ENT_LEN];
	unsigned char algo;
	int retcode, reqlen;
	
	if( (*point_to_OPmode == NotDefined) || ((*point_to_ModuleAvailable & CTRDRBG_Enabled) != CTRDRBG_Enabled) )
		return -3;
		
	if( !output || (request_num_of_bits <= 0) )
		return -4;

	if( !genEntropy(ent1, ENT_LEN) ) return -5;
	if( !genEntropy(ent2, ENT_LEN) ) return -5;
	if( !genEntropy(ent3, ENT_LEN) ) return -5;
	if( !genEntropy(ent4, ENT_LEN) ) return -5;
	if( !genEntropy(ent5, ENT_LEN) ) return -5;
	if( !genEntropy(ent6, ENT_LEN) ) return -5;
	if( !genEntropy(ent7, ENT_LEN) ) return -5;
	if( !genEntropy(ent8, ENT_LEN) ) return -5;
	if( !genEntropy(ent9, ENT_LEN) ) return -5;
	if( !genEntropy(&algo, 1) ) return -5;

	algo = (unsigned char)(((int)algo) * 4 / 256);

	switch(algo)
	{
		case 0:
			algo = DRBG_ALGO_SEED;
			break;
			
		case 1:
			algo = DRBG_ALGO_ARIA128;
			break;
			
		case 2:
			algo = DRBG_ALGO_ARIA192;
			break;

		case 3:
			algo = DRBG_ALGO_ARIA256;
			break;

		default:
			return -5;
	}

	if( (retcode = CTR_DRBG_Instantiate(&drbg, algo, ent1, ENT_LEN, ent2, ENT_LEN, ent3, ENT_LEN, USE_DERIVATION_FUNCTION)) != 1)
	{
		CTR_DRBG_clear(&drbg);
		return retcode;
	}
		
	if( (retcode = CTR_DRBG_Reseed(&drbg, ent4, ENT_LEN, ent5, ENT_LEN)) != 1 )
	{
		CTR_DRBG_clear(&drbg);
		return retcode;
	}
	
	if( (retcode = CTR_DRBG_Generate(&drbg, output, request_num_of_bits, ent6, ENT_LEN)) != 1 )
	{
		CTR_DRBG_clear(&drbg);
		return retcode;
	}
		
	if( (retcode = CTR_DRBG_Reseed(&drbg, ent7, ENT_LEN, ent8, ENT_LEN)) != 1 )
	{
		CTR_DRBG_clear(&drbg);
		return retcode;
	}
	
	if( (retcode = CTR_DRBG_Generate(&drbg, output, request_num_of_bits, ent9, ENT_LEN)) != 1 )
	{
		CTR_DRBG_clear(&drbg);
		return retcode;
	}
	
	reqlen = request_num_of_bits/8;
	
	if( !memcmp( output, ent1, (reqlen > ENT_LEN)? ENT_LEN : reqlen ) )
	{
		return -5;
	}
	
	if( !memcmp( output, ent4, (reqlen > ENT_LEN)? ENT_LEN : reqlen ) )
	{
		return -5;
	}
	
	if( !memcmp( output, ent7, (reqlen > ENT_LEN)? ENT_LEN : reqlen ) )
	{
		return -5;
	}	

	CTR_DRBG_clear(&drbg);
	return 1;
}

int CTR_DRBG_ValidTest()
{
	CTR_DRBG_STATE drbg;
	
	unsigned char entropy1[16] = {0x39, 0x0a, 0x78, 0xff, 0xaa, 0xd6, 0xfc, 0xfe, 0x47, 0x6d, 0x2a, 0xda, 0xc3, 0x0a, 0x63, 0x3b};
	unsigned char nonce1[8] = {0xb5, 0x33, 0x24, 0x80, 0x91, 0xe2, 0x93, 0x03};
	unsigned char person1[16] = {0xd7, 0xe3, 0x58, 0x9e, 0x8a, 0x7d, 0xae, 0x6e, 0xe4, 0x54, 0xba, 0xd6, 0x48, 0x8e, 0x1b, 0xc7};
	unsigned char additional1[16] = {0x78, 0x35, 0xc2, 0x3f, 0x08, 0xdc, 0x04, 0x10, 0x13, 0x86, 0xed, 0xe3, 0x2c, 0xc3, 0xd8, 0x7c};
	unsigned char entreseed1[16] = {0x97, 0x1c, 0x3c, 0x40, 0xba, 0xb1, 0xc9, 0xf4, 0xce, 0x21, 0xb4, 0xc7, 0xda, 0xaa, 0x4f, 0x93};
	unsigned char addreseed1[16] = {0xe2, 0x92, 0xdc, 0x60, 0x5b, 0xc5, 0xa3, 0x2a, 0xe3, 0xbf, 0x42, 0xe4, 0x2f, 0xac, 0x45, 0xbc};
	unsigned char additional1_2[16] = {0x45, 0xce, 0xf6, 0xa1, 0xeb, 0x20, 0x76, 0x02, 0x5f, 0x39, 0x0d, 0xd9, 0x48, 0x72, 0xbf, 0xe9};
	unsigned char randTV1[16] = {0xc5, 0x72, 0x29, 0xd4, 0x9a, 0x4a, 0x34, 0xcd, 0x22, 0xe3, 0x9e, 0x09, 0x49, 0x00, 0x64, 0xa2};
	unsigned char randomout1[16];

	unsigned char entropy2[16] = {0xe4, 0x69, 0x1d, 0x2b, 0xb5, 0x6a, 0xff, 0x13, 0x93, 0x4c, 0x26, 0x7c, 0xfa, 0x6e, 0x00, 0x6e};
	unsigned char nonce2[8] = {0xe7, 0xa4, 0xa2, 0xf9, 0x32, 0x3a, 0xba, 0x63};
	unsigned char person2[16] = {0x1e, 0x36, 0xc4, 0x86, 0x2f, 0xde, 0x81, 0x73, 0x3b, 0x7a, 0xa5, 0x5b, 0xc4, 0x5b, 0xd0, 0xb0};
	unsigned char additional2[16] = {0x85, 0x1c, 0xc0, 0x87, 0x4b, 0x28, 0xc5, 0x41, 0x06, 0x7c, 0x75, 0x6a, 0x20, 0xaf, 0xa0, 0xe1};
	unsigned char entreseed2[16] = {0x0d, 0x2f, 0x87, 0x39, 0x24, 0xcd, 0x48, 0x60, 0xad, 0x7c, 0x9d, 0x7e, 0x3b, 0x55, 0xc6, 0x20};
	unsigned char addreseed2[16] = {0x3c, 0xdf, 0xc4, 0x96, 0xce, 0x8e, 0xc8, 0x99, 0xd4, 0x89, 0xeb, 0x32, 0x49, 0xb0, 0x1f, 0xd7};
	unsigned char additional2_2[16] = {0xd5, 0xde, 0x66, 0xd6, 0x9e, 0x6b, 0x42, 0xf7, 0x61, 0xf6, 0x6c, 0x5c, 0xc1, 0x61, 0xc8, 0xad};
	unsigned char randTV2[16] = {0xcd, 0x3a, 0xa7, 0x11, 0xa5, 0xa1, 0x3a, 0x23, 0x19, 0x23, 0x4c, 0x31, 0xc3, 0x96, 0xac, 0x4a};
	unsigned char randomout2[16];

#ifndef _MicroC_OS_MOD_
	unsigned char entropy3[24] = {0xdd, 0x8b, 0x8f, 0x4a, 0xf7, 0xbf, 0xa8, 0x1b, 0x6d, 0xec, 0xbf, 0x47, 0xdb, 0x05, 0x83, 0x09, 0xa6, 0xb3, 0x8f, 0xe7, 0x48, 0x54, 0x53, 0xdb};
	unsigned char nonce3[16] = {0xe8, 0x45, 0x52, 0xb1, 0x2e, 0x5c, 0x8f, 0xb0, 0x55, 0xb9, 0x41, 0x7c, 0x82, 0xbf, 0xce, 0x3b};
	unsigned char person3[32] = {0x54, 0x5d, 0xf7, 0xf7, 0xbc, 0x92, 0x50, 0x43, 0x0f, 0x30, 0xf4, 0x22, 0x59, 0xe0, 0x76, 0x24, 0xf5, 0x66, 0x1b, 0xd2, 0x5a, 0x26, 0x46, 0x4c, 0x38, 0xe7, 0x33, 0x31, 0xc4, 0xd8, 0xe8, 0xbf};
	unsigned char additional3[32] = {0x4f, 0xd0, 0x69, 0x3c, 0x1e, 0xda, 0x2c, 0x94, 0x76, 0xf1, 0xcc, 0x43, 0xf6, 0x08, 0x01, 0x75, 0x2a, 0x4e, 0xd0, 0x6c, 0x5c, 0xaf, 0xff, 0x23, 0xad, 0x9e, 0xcc, 0x31, 0x65, 0x12, 0xdf, 0xef};
	unsigned char entreseed3[24] = {0x88, 0xce, 0x7c, 0xdd, 0xaa, 0xe6, 0xfd, 0x42, 0x03, 0x7f, 0x80, 0x13, 0xc6, 0xd6, 0xdd, 0x16, 0xaf, 0x84, 0xdb, 0x47, 0xdb, 0x00, 0xa3, 0x7b};
	unsigned char addreseed3[32] = {0xdd, 0x65, 0x74, 0x43, 0x0e, 0x75, 0x99, 0x13, 0x24, 0xde, 0x98, 0xa4, 0x07, 0xbd, 0xad, 0x96, 0xe0, 0x61, 0x76, 0x5a, 0x72, 0x51, 0xf0, 0x4f, 0xad, 0x90, 0xa2, 0x2b, 0x80, 0x1f, 0x18, 0x9d};
	unsigned char additional3_2[32] = {0xf0, 0xc4, 0x93, 0x31, 0x67, 0x0a, 0xff, 0x73, 0x4e, 0x89, 0x25, 0x57, 0xdd, 0x67, 0x22, 0xd8, 0x32, 0x1f, 0x18, 0xe0, 0xa1, 0x81, 0x23, 0x68, 0x4c, 0xfb, 0x8f, 0xe0, 0xf3, 0x16, 0x48, 0xd1};
	unsigned char randTV3[16] = {0x95, 0x3d, 0x00, 0x84, 0x70, 0x72, 0x31, 0xc9, 0xd5, 0xee, 0x35, 0x73, 0x6a, 0x3e, 0x8c, 0x98};
	unsigned char randomout3[16];

	unsigned char entropy4[32] = {0x5f, 0xaf, 0x96, 0x8d, 0x13, 0xea, 0x1c, 0x92, 0x7c, 0x8d, 0xdc, 0x98, 0xda, 0x65, 0xc0, 0xf0, 0x0a, 0x6b, 0x26, 0x8c, 0x08, 0x3e, 0x89, 0x11, 0xb2, 0xd1, 0x5d, 0x2e, 0xcf, 0x61, 0x3a, 0x2d};
	unsigned char nonce4[16] = {0x4f, 0xab, 0x3d, 0xc7, 0xd4, 0x5b, 0xac, 0x3d, 0x72, 0xc7, 0xd8, 0xa4, 0xb3, 0xdd, 0x48, 0x80};
	unsigned char person4[32] = {0xdf, 0x5a, 0x13, 0x95, 0x7a, 0x3e, 0x8e, 0xfa, 0x0d, 0x7c, 0x27, 0x6f, 0x2a, 0xf5, 0x91, 0xf0, 0xaa, 0xa7, 0x22, 0x8b, 0x39, 0x22, 0x79, 0x6e, 0x15, 0x3c, 0x63, 0x44, 0x12, 0x06, 0x00, 0xc2};
	unsigned char additional4[32] = {0xe2, 0xff, 0x21, 0x7c, 0x93, 0x87, 0xf5, 0xfe, 0x59, 0x96, 0xe5, 0x18, 0x8e, 0xad, 0xbc, 0x79, 0xf7, 0x0d, 0x0b, 0x7f, 0x49, 0x28, 0xcc, 0x4e, 0xeb, 0x55, 0x45, 0x20, 0xfe, 0xc7, 0x2f, 0xdc};
	unsigned char entreseed4[32] = {0x9b, 0xc0, 0x18, 0xe9, 0x5b, 0x02, 0x06, 0x44, 0x1d, 0x87, 0x5d, 0xd0, 0x03, 0x71, 0x02, 0xee, 0xbe, 0x44, 0xc1, 0x4e, 0x0c, 0x53, 0xec, 0x05, 0x7e, 0x78, 0x45, 0xdf, 0x7f, 0x08, 0x1e, 0xf6};
	unsigned char addreseed4[32] = {0x92, 0x06, 0xbf, 0x83, 0xdb, 0x97, 0x08, 0xf5, 0xe1, 0xb6, 0x58, 0x40, 0x92, 0x29, 0xad, 0x78, 0x88, 0xb4, 0x0c, 0x9e, 0x8a, 0x8c, 0x23, 0xba, 0x56, 0x0e, 0x2d, 0x29, 0x9d, 0xb1, 0x16, 0x39};
	unsigned char additional4_2[32] = {0x50, 0x3a, 0xdf, 0xf3, 0x1a, 0x2f, 0x45, 0x38, 0x2e, 0x8d, 0x9d, 0x10, 0x42, 0xbd, 0x03, 0x3e, 0xdb, 0xc5, 0xb3, 0x18, 0xcc, 0xbc, 0xb7, 0x95, 0xf9, 0x80, 0xc3, 0xa8, 0x61, 0xab, 0x5d, 0xcc};
	unsigned char randTV4[16] = {0xa8, 0x70, 0xfb, 0x91, 0xf9, 0x86, 0x24, 0x49, 0x55, 0x69, 0x1c, 0x2f, 0x86, 0x26, 0x2d, 0x5d};
	unsigned char randomout4[16];
#endif

	int check = 1;

#ifdef PRINT_MODE
	Print_Result("\n==================================\n");
	Print_Result(" CTR-DRBG(KU API) Validation TEST\n");
	Print_Result("==================================\n");
#endif

	CTR_DRBG_Instantiate(&drbg, DRBG_ALGO_SEED, entropy1, 16, nonce1, 8, person1, 16, USE_DERIVATION_FUNCTION);
	CTR_DRBG_Generate(&drbg, randomout1, 128, additional1, 16);
	CTR_DRBG_Reseed(&drbg, entreseed1, 16, addreseed1, 16);
	CTR_DRBG_Generate(&drbg, randomout1, 128, additional1_2, 16);

	if(!memcmp(randomout1, randTV1, 16))
	{
		//Print_Result("CTR-DRBG(SEED) Validation TEST OK\n");
	}
	else
	{
#ifdef PRINT_MODE
		Print_Result("-- CTR-DRBG(SEED) Validation TEST Fail\n");
#endif
		check = 0;
	}

	CTR_DRBG_Instantiate(&drbg, DRBG_ALGO_ARIA128, entropy2, 16, nonce2, 8, person2, 16, USE_DERIVATION_FUNCTION);
	CTR_DRBG_Generate(&drbg, randomout2, 128, additional2, 16);
	CTR_DRBG_Reseed(&drbg, entreseed2, 16, addreseed2, 16);
	CTR_DRBG_Generate(&drbg, randomout2, 128, additional2_2, 16);

	if(!memcmp(randomout2, randTV2, 16))
	{
		//Print_Result("CTR-DRBG(ARIA-128) Validation TEST OK\n");
	}
	else
	{
#ifdef PRINT_MODE
		Print_Result("-- CTR-DRBG(ARIA-128) Validation TEST Fail\n");
#endif
		check = 0;
	}

#ifndef _MicroC_OS_MOD_
	CTR_DRBG_Instantiate(&drbg, DRBG_ALGO_ARIA192, entropy3, 24, nonce3, 16, person3, 32, USE_DERIVATION_FUNCTION);
	CTR_DRBG_Generate(&drbg, randomout3, 128, additional3, 32);
	CTR_DRBG_Reseed(&drbg, entreseed3, 24, addreseed3, 32);
	CTR_DRBG_Generate(&drbg, randomout3, 128, additional3_2, 32);

	if(!memcmp(randomout3, randTV3, 16))
	{
		//Print_Result("CTR-DRBG(ARIA-192) Validation TEST OK\n");
	}
	else
	{
#ifdef PRINT_MODE
		Print_Result("-- CTR-DRBG(ARIA-192) Validation TEST Fail\n");
#endif
		check = 0;
	}

	CTR_DRBG_Instantiate(&drbg, DRBG_ALGO_ARIA256, entropy4, 32, nonce4, 16, person4, 32, USE_DERIVATION_FUNCTION);
	CTR_DRBG_Generate(&drbg, randomout4, 128, additional4, 32);
	CTR_DRBG_Reseed(&drbg, entreseed4, 32, addreseed4, 32);
	CTR_DRBG_Generate(&drbg, randomout4, 128, additional4_2, 32);

	if(!memcmp(randomout4, randTV4, 16))
	{
		//Print_Result("CTR-DRBG(ARIA-256) Validation TEST OK\n");
	}
	else
	{
#ifdef PRINT_MODE
		Print_Result("-- CTR-DRBG(ARIA-256) Validation TEST Fail\n");
#endif
		check = 0;
	}
#endif
	
	CTR_DRBG_clear(&drbg);

	return check;
}

#ifndef _MicroC_OS_MOD_
	#define MAX_TEST_COUNT 10
#else
	#define MAX_TEST_COUNT 10
#endif

int CTR_DRBG_RandomGenTest()
{
	unsigned char output[MAX_TEST_COUNT][20] = { {0x00, }, };
	int i, j, check = 1;
	int z; //add
#ifdef PRINT_MODE
	Print_Result("\n=========================================\n");
	Print_Result(" CTR-DRBG(KU API) Random Generation TEST\n");
	Print_Result("=========================================\n");
#endif

	for(i=0;i<MAX_TEST_COUNT;i++)
	{
		CTR_DRBG_Random_Gen(&output[i][0], 160);
	}

	for(i=0;i<MAX_TEST_COUNT;i++)
	{
		printf("output %d: ",i);
		for(z=0;z<20;z++){
			printf("%02X",output[i][z]);
		}
		printf("\n");
		for(j=0;j<MAX_TEST_COUNT;j++)
		{
			if(i == j)
				continue;

			if(!memcmp(output[i], output[j], 20))
			{
#ifdef PRINT_MODE
				
	#ifdef _MicroC_OS_MOD_
				printf("Same is exist where i = %d, j = %d\n\n", i, j);
				
	#else
				/*printf("output j: ");
				for(z=0;z<strlen(output[j]);z++){
					printf("%02X",output[j][z]);

				}
				printf("\n");*/
				fprintf(stderr, "Same is exist where i = %d, j = %d\n\n", i, j);	
	#endif
#endif
				check = 0;
			}
		}
	}

	return check;
}
