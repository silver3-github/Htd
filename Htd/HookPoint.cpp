#include "HookPoint.h"

//INT3 HookPoint����

HookPoint::HookPoint(void* address, unsigned len, HookProc hookProc, void* retAdr, BOOL  isOnce)
{
	//�������ݱ���
	this->address = address;
	this->hookProc = hookProc;
	this->retAdr = retAdr;
	this->isOnce = isOnce;
	this->oldCode = *((char*)address);
	memset(fixCode, 0xCC, sizeof(fixCode));
	DWORD oldProtect;
	VirtualProtect(fixCode, sizeof(fixCode), PAGE_EXECUTE_READWRITE, &oldProtect);

	//�����޸�����
#ifdef _WIN64
	this->jmpAdr = (void*)((DWORD_PTR)address + len);

	unsigned char* order = (unsigned char*)address;
	unsigned short* order2 = (unsigned short*)address;
	switch (*order)//һ�ֽ�ָ���޸� 
	{
	case 0xE8://CALL 4�ֽڣ�����ǰ��������������
	case 0xE9://JMP  4�ֽ�
	{
		int* adr = (int*)((DWORD_PTR)address + 1);
		this->fixAdr = (void*)(((DWORD_PTR)address + 5) + *adr);
		fixCode[0] = 0xFF;
		fixCode[1] = *order == 0xE8 ? 0x15 : 0x25;// 0xFF15 call/0xFF25 jmp 
		adr = (int*)(fixCode + 2);
		*adr = (DWORD_PTR)&this->fixAdr - ((DWORD_PTR)fixCode + 6);

		fixCode[6] = 0xFF;
		fixCode[7] = 0x25;  //0xFF25 jmp
		adr = (int*)(fixCode + 8);
		*adr = (DWORD_PTR)&this->jmpAdr - ((DWORD_PTR)fixCode + 12);
		break;
	}
	case 0xEB://JMP  1�ֽ�
	case 0xE3://JRCXZ  1�ֽ�
	case 0x70://JO  1�ֽ�
	case 0x71://JNO 1�ֽ�
	case 0x72://JB/JC/JNAE  1�ֽ�
	case 0x73://JNB/JNC/JAE  1�ֽ�
	case 0x74://JE/JZ  1�ֽ�
	case 0x75://JNE/JNZ  1�ֽ�
	case 0x76://JNA/JBE  1�ֽ�
	case 0x77://JA/JNBE  1�ֽ�
	case 0x78://JS  1�ֽ�
	case 0x79://JNS  1�ֽ�
	case 0x7A://JP/JPE  1�ֽ�
	case 0x7B://JNP/JPO  1�ֽ�
	case 0x7C://JL/JNGE  1�ֽ�
	case 0x7D://JNL/JGE  1�ֽ�
	case 0x7E://JNG/JLE  1�ֽ�
	case 0x7F://JG/JNLE  1�ֽ�
	{
		char* offset = (char*)((DWORD_PTR)address + 1);
		this->fixAdr = (void*)(((DWORD_PTR)address + 2) + *offset);
		fixCode[0] = *order;
		fixCode[1] = 6;
		fixCode[8] = 0xFF;
		fixCode[9] = 0x25;  //0xFF25 jmp
		int* adr = (int*)(fixCode + 10);
		*adr = (DWORD_PTR)&this->fixAdr - ((DWORD_PTR)fixCode + 14);

		fixCode[2] = 0xFF;
		fixCode[3] = 0x25;  //0xFF25 jmp
		adr = (int*)(fixCode + 4);
		*adr = (DWORD_PTR)&this->jmpAdr - ((DWORD_PTR)fixCode + 8);
		break;
	}
	default:
		switch (*order2)//���ֽ�ָ���޸�  
		{
		case 0xFF15://CALL  ��ŵ�ַ�ĵ�ַ(ƫ��)
		case 0xFF25://JMP   ��ŵ�ַ�ĵ�ַ(ƫ��)
		{
			int* adr = (int*)((DWORD_PTR)address + 2);
			void** fixAdr = (void**)((DWORD_PTR)address + 6 + *adr);
			this->fixAdr = *fixAdr;
			fixCode[0] = 0xFF;
			fixCode[1] = *order2 == 0xFF15 ? 0x15 : 0x25;// 0xFF15 call/0xFF25 jmp 
			adr = (int*)(fixCode + 2);
			*adr = (DWORD_PTR)&this->fixAdr - ((DWORD_PTR)fixCode + 6);

			fixCode[6] = 0xFF;
			fixCode[7] = 0x25;  //0xFF25 jmp
			adr = (int*)(fixCode + 8);
			*adr = (DWORD_PTR)&this->jmpAdr - ((DWORD_PTR)fixCode + 12);
			break;
		}
		case 0x0F80://JO  4�ֽڣ�ƫ��ֵ��
		case 0x0F81://JNO 4�ֽڣ�ƫ��ֵ��
		case 0x0F82://JB/JC/JNAE  4�ֽڣ�ƫ��ֵ��
		case 0x0F83://JNB/JNC/JAE  4�ֽڣ�ƫ��ֵ��
		case 0x0F84://JE/JZ  4�ֽڣ�ƫ��ֵ��
		case 0x0F85://JNE/JNZ  4�ֽڣ�ƫ��ֵ��
		case 0x0F86://JNA/JBE  4�ֽڣ�ƫ��ֵ��
		case 0x0F87://JA/JNBE  4�ֽڣ�ƫ��ֵ��
		case 0x0F88://JS  4�ֽڣ�ƫ��ֵ��
		case 0x0F89://JNS  4�ֽڣ�ƫ��ֵ��
		case 0x0F8A://JP/JPE  4�ֽڣ�ƫ��ֵ��
		case 0x0F8B://JNP/JPO  4�ֽڣ�ƫ��ֵ��
		case 0x0F8C://JL/JNGE  4�ֽڣ�ƫ��ֵ��
		case 0x0F8D://JNL/JGE  4�ֽڣ�ƫ��ֵ��
		case 0x0F8E://JNG/JLE  4�ֽڣ�ƫ��ֵ��
		case 0x0F8F://JG/JNLE  4�ֽڣ�ƫ��ֵ��
		{
			int* adr = (int*)((DWORD_PTR)address + 2);
			this->fixAdr = (void*)(((DWORD_PTR)address + 6) + *adr);
			fixCode[0] = order[1] - 0x10;
			fixCode[1] = 6;
			fixCode[8] = 0xFF;
			fixCode[9] = 0x25;  //0xFF25 jmp
			adr = (int*)(fixCode + 10);
			*adr = (DWORD_PTR)&this->fixAdr - ((DWORD_PTR)fixCode + 14);

			fixCode[2] = 0xFF;
			fixCode[3] = 0x25;  //0xFF25 jmp
			adr = (int*)(fixCode + 4);
			*adr = (DWORD_PTR)&this->jmpAdr - ((DWORD_PTR)fixCode + 8);
			break;
		}
		default:
		{
			memcpy(fixCode, address, len);
			fixCode[len] = 0xFF;
			fixCode[len + 1] = 0x25;  //0xFF25 jmp
			int* adr = (int*)(fixCode + len + 2);
			*adr = (DWORD_PTR)&this->jmpAdr - ((DWORD_PTR)fixCode + len + 6);
		}
		}
	}
#else
	unsigned char* order = (unsigned char*)address;
	unsigned short* order2 = (unsigned short*)address;
	switch (*order)//һ�ֽ�ָ���޸� 
	{
	case 0xE8://CALL 4�ֽڣ�����ǰ��������������
	case 0xE9://JMP  4�ֽ�
	{
		int* adr = (int*)((DWORD_PTR)address + 1);
		DWORD_PTR target = (DWORD_PTR)address + 5 + *adr;
		fixCode[0] = *order;
		adr = (int*)(fixCode + 1);
		*adr = target - ((DWORD_PTR)fixCode + 5);

		fixCode[len] = 0xE9;
		adr = (int*)(fixCode + len + 1);
		*adr = ((DWORD_PTR)address + len) - ((DWORD_PTR)fixCode + len + 5);
		break;
	}
	case 0xEB://JMP  1�ֽ�
	case 0xE3://JECXZ  1�ֽ�
	case 0x70://JO  1�ֽ�
	case 0x71://JNO  1�ֽ�
	case 0x72://JB/JC/JNAE  1�ֽ�
	case 0x73://JNB/JNC/JAE  1�ֽ�
	case 0x74://JE/JZ  1�ֽ�
	case 0x75://JNE/JNZ  1�ֽ�
	case 0x76://JNA/JBE  1�ֽ�
	case 0x77://JA/JNBE  1�ֽ�
	case 0x78://JS  1�ֽ�
	case 0x79://JNS  1�ֽ�
	case 0x7A://JP/JPE  1�ֽ�
	case 0x7B://JNP/JPO  1�ֽ�
	case 0x7C://JL/JNGE  1�ֽ�
	case 0x7D://JNL/JGE  1�ֽ�
	case 0x7E://JNG/JLE  1�ֽ�
	case 0x7F://JG/JNLE  1�ֽ�
	{
		char* offset = (char*)((DWORD_PTR)address + 1);
		DWORD_PTR target = (DWORD_PTR)address + 2 + *offset;
		fixCode[0] = *order;
		fixCode[1] = 5;
		fixCode[7] = 0xE9;
		int* adr = (int*)(fixCode + 8);
		*adr = target - ((DWORD_PTR)fixCode + 12);

		fixCode[2] = 0xE9;
		adr = (int*)(fixCode + 3);
		*adr = ((DWORD_PTR)address + len) - ((DWORD_PTR)fixCode + 7);
		break;
	}
	default:
		switch (*order2)//���ֽ�ָ���޸�  
		{
		case 0x0F80://JO  4�ֽڣ�ƫ��ֵ��
		case 0x0F81://JNO 4�ֽڣ�ƫ��ֵ��
		case 0x0F82://JB/JC/JNAE  4�ֽڣ�ƫ��ֵ��
		case 0x0F83://JNB/JNC/JAE  4�ֽڣ�ƫ��ֵ��
		case 0x0F84://JE/JZ  4�ֽڣ�ƫ��ֵ��
		case 0x0F85://JNE/JNZ  4�ֽڣ�ƫ��ֵ��
		case 0x0F86://JNA/JBE  4�ֽڣ�ƫ��ֵ��
		case 0x0F87://JA/JNBE  4�ֽڣ�ƫ��ֵ��
		case 0x0F88://JS  4�ֽڣ�ƫ��ֵ��
		case 0x0F89://JNS  4�ֽڣ�ƫ��ֵ��
		case 0x0F8A://JP/JPE  4�ֽڣ�ƫ��ֵ��
		case 0x0F8B://JNP/JPO  4�ֽڣ�ƫ��ֵ��
		case 0x0F8C://JL/JNGE  4�ֽڣ�ƫ��ֵ��
		case 0x0F8D://JNL/JGE  4�ֽڣ�ƫ��ֵ��
		case 0x0F8E://JNG/JLE  4�ֽڣ�ƫ��ֵ��
		case 0x0F8F://JG/JNLE  4�ֽڣ�ƫ��ֵ��
		{
			int* adr = (int*)((DWORD_PTR)address + 2);
			DWORD_PTR target = (DWORD_PTR)address + 6 + *adr;
			fixCode[0] = order[0];
			fixCode[1] = order[1];
			adr = (int*)(fixCode + 2);
			*adr = target - ((DWORD_PTR)fixCode + 6);

			fixCode[len] = 0xE9;
			adr = (int*)(fixCode + len + 1);
			*adr = ((DWORD_PTR)address + len) - ((DWORD_PTR)fixCode + len + 5);
			break;
		}
		default:
			memcpy(fixCode, address, len);
			fixCode[len] = 0xE9;
			int* adr = (int*)(fixCode + len + 1);
			*adr = ((DWORD_PTR)address + len) - ((DWORD_PTR)fixCode + len + 5);
		}
	}
#endif
}
