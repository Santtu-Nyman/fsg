/*
	File splitter gatherer tool 1.0.1 2019-02-07 by Santtu Nyman.
	git repository https://github.com/Santtu-Nyman/fsg

	Description
		Simple command line tool for splitting large files to smaller fragment files
		and reassembling fragment files to back to single file.
		Instructions how to use the program are contained in the program and printed out with -h or --help parameter.

	Version history
		Version 1.0.2 2019-02-07
			Added macro to remove silly Microsoft specific warnings.
		version 1.0.0 2018-12-31
			First version of the program.
*/

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

#define FSG_DEFAULT_BUFFER_SIZE ((size_t)1 << (size_t)20)

#define FSG_OPERATING_MODE_UNKNOWN 0
#define FSG_OPERATING_MODE_SPLIT 1
#define FSG_OPERATING_MODE_GATHER 2
#define FSG_OPERATING_MODE_INVALID -1

#define FSG_ERROR_HINT_NONE 0
#define FSG_ERROR_HINT_PARAMETER 1
#define FSG_ERROR_HINT_DATA 2
#define FSG_ERROR_HINT_MEMORY 3
#define FSG_ERROR_HINT_INPUT_OPEN 4
#define FSG_ERROR_HINT_INPUT_READ 5
#define FSG_ERROR_HINT_OUTPUT_OPEN 6
#define FSG_ERROR_HINT_OUTPUT_WRITE 7

void print_instructions();
/*
	Description
		Function writes instructions how to use the program to console.
	Parameters
		Function has no parameters.
	Return
		Function has no return value.
*/

int is_help_asked(int argc, char** argv);
/*
	Description
		Function checks if -h or --help argument was given.
	Parameters
		argc
			Number of arguments pointed by parameter argv.
		argv
			Pointer to array of pointers to argument null terminated strings.
	Return
		If help argument was the return value is nonzero and zero if the argument was not given.
*/

int get_operating_mode(int argc, char** argv);
/*
	Description
		Function reads desired operating mode from process arguments.
		Operating mode is specified by the next argument after -m or --mode argument split or s specifies split mode and gather or g gather mode.
	Parameters
		argc
			Number of arguments pointed by parameter argv.
		argv
			Pointer to array of pointers to argument null terminated strings.
	Return
		Function returns number representing operating mode.
*/

int get_fragment_size(int argc, char** argv, uint32_t* fragment_size);
/*
	Description
		Function reads desired size of fragments input file is split to in bytes.
		fragment size is specified by the next argument after -s or --size argument.
		Next after fragment size can be used to specify unit used in fragment size argument.
		If no unit is specified fragment size read in bytes.
	Parameters
		argc
			Number of arguments pointed by parameter argv.
		argv
			Pointer to array of pointers to argument null terminated strings.
		fragment_size
			Pointer to variable that receives the size of fragment files.
	Return
		If function succeeds the return value is zero.
		If the function fails the return value is error code.
*/

char* get_file_name(int argc, char** argv);
/*
	Description
		Function reads desired name of the complete nonfragmented file from process arguments.
		File name is specified by the next argument after -f or --file_name.
	Parameters
		argc
			Number of arguments pointed by parameter argv.
		argv
			Pointer to array of pointers to argument null terminated strings.
	Return
		Function returns pointer from argument strings given by argv parameter that specifies the file name
		if it is given once. If file name parameter was not given the return value is zero.
*/

char* get_fragment_name_prefix(int argc, char** argv);
/*
	Description
		Function reads desired prefix of fragment names from process arguments.
		Fragment name prefix is specified by the next argument after -p or --fragment_prefix.
	Parameters
		argc
			Number of arguments pointed by parameter argv.
		argv
			Pointer to array of pointers to argument null terminated strings.
	Return
		Function returns pointer from argument strings given by argv parameter that specifies the fragment file name prefix
		if it is given once. If prefix parameter was not given the return value is zero.
*/

int is_readable_file(const char* file_name);
/*
	Description
		Function test if file is readable.
	Parameters
		file_name
			Pointer to null terminated string specifieng name of the file to be tested.
	Return
		If file is successfully opened the return value is nonzero and zero if file was not opened.
*/

int try_to_write_test_fragment(const char* fragment_name_prefix);
/*
	Description
		Function tries to create writable test fragment file that has given prefix and index 4294967295.
		The test file is deleted after testing.
	Parameters
		fragment_name_prefix
			Pointer to null terminated string specifieng prefix of the fragment name files.
	Return
		If file is successfully opened the return value is nonzero and zero if file was not opened.
*/

int count_fragments(const char* fragment_name_prefix, uint32_t* fragment_count);
/*
	Description
		Function counts number of frament files that have given prefix.
	Parameters
		fragment_name_prefix
			Pointer to null terminated string specifieng prefix of the fragment name files.
		fragment_count
			Pointer to variable that receives the number of fragment files.
	Return
		If function succeeds the return value is zero.
		If the function fails the return value is error code.
*/

void write_fragment_file_name(const char* fragment_name_prefix, char* file_name_buffer, uint32_t fragment_number);
/*
	Description
		Function writes fragment file name to buffer.
		Fragment name is prefix followed by fragment number and .dat file extension.
	Parameters
		fragment_name_prefix
			Pointer to null terminated string specifieng prefix of the fragment name files.
		file_name_buffer
			Pointer to buffer that receives fragment file name as null terminated string.
			The buffer needs to be big enough to store maximum fragment file name length which is prefix length plus 15 characters.
		fragment_number
			number if the fragment file.
	Return
		Function has no return value.
*/

int spit_file_to_fragments(size_t buffer_size, const char* file_name, const char* fragment_name_prefix, uint32_t fragment_size, uint32_t* fragment_count, int* error_hint);
/*
	Description
		Function reads file specified by file_name parameter and spits it to fragment files.
		Fragment files will be written in ascending order and from the input file.
		Fragment files are named fragment name prefix followed by fragment number and .dat file extension.
		Size of fragments is specified by fragment_size parameter. The last fragment can be smaller then fragment size.
		Files larger than buffer size are processed in buffer sized blocks.
	Parameters
		buffer_size
			Size of buffer used for storing file data temporary in memory.
		file_name
			Pointer to null terminated string specifieng source file for the fragment files.
		fragment_name_prefix
			Pointer to null terminated string specifieng prefix of the fragment name files.
		fragment_size
			Size of fragment files.
		fragment_count
			Pointer to variable that receives number of fragment files.
		error_hint
			pointer to variable that receives error hint code.
	Return
		If function succeeds the return value is zero.
		If the function fails the return value is error code.
*/

int gather_fragments_to_file(size_t buffer_size, const char* file_name, const char* fragment_name_prefix, uint32_t fragment_count, int* error_hint);
/*
	Description
		Function reads fragment files in ascending order to single file specified by file_name parameter.
		Fragment files are named fragment name prefix followed by fragment number and .dat file extension.
		Files larger than buffer size are processed in buffer sized blocks.
	Parameters
		buffer_size
			Size of buffer used for storing file data temporary in memory.
		file_name
			Pointer to null terminated string specifieng name of the destination file where the fragments are collected.
		fragment_name_prefix
			Pointer to null terminated string specifieng prefix of the fragment name files.
		fragment_count
			Number of fragment files.
		error_hint
			pointer to variable that receives error hint code.
	Return
		If function succeeds the return value is zero.
		If the function fails the return value is error code.
*/

int main(int argc, char** argv)
{
	if (!is_help_asked(argc, argv))
	{
		int mode = get_operating_mode(argc, argv);
		if (mode == FSG_OPERATING_MODE_SPLIT)
		{
			char* file_name = get_file_name(argc, argv);
			if (!file_name)
			{
				printf("Invalid parameters. No file input name specified.\n");
				print_instructions();
				return EINVAL;
			}
			char* fragment_name_prefix = get_fragment_name_prefix(argc, argv);
			if (!file_name)
			{
				printf("Invalid parameters. No fragment file name prefix specified.\n");
				print_instructions();
				return EINVAL;
			}
			uint32_t fragment_size;
			int error = get_fragment_size(argc, argv, &fragment_size);
			if (error)
			{
				if (error == EINVAL)
				{
					printf("Invalid parameters. No fragment file size specified.\n");
					print_instructions();
				}
				else
					printf("Unknown error occurred when trying to get fragment file size from process arguments.\n");
				return error;
			}
			if (!is_readable_file(file_name))
			{
				printf("Unable to read from input file \"%s\".", file_name);
				return EINVAL;
			}
			if (!try_to_write_test_fragment(fragment_name_prefix))
			{
				printf("Unable to write fragment files with prefix \"%s\".", file_name);
				return EINVAL;
			}
			uint32_t fragment_count;
			int error_hint;
			error = spit_file_to_fragments(FSG_DEFAULT_BUFFER_SIZE, file_name, fragment_name_prefix, fragment_size, &fragment_count, &error_hint);
			if (!error)
				printf("Split successful. File \"%s\" slit to %lu fragment files.\n", file_name, fragment_count);
			else
			{
				switch (error_hint)
				{
					case FSG_ERROR_HINT_PARAMETER :
						printf("Invalid parameters.\n");
						print_instructions();
						break;
					case FSG_ERROR_HINT_MEMORY:
						printf("Memory allocation failed.\n");
						break;
					case FSG_ERROR_HINT_INPUT_OPEN:
						printf("Unable to read from input file \"%s\".", file_name);
						break;
					case FSG_ERROR_HINT_INPUT_READ:
						printf("Unable to read from input file \"%s\".", file_name);
						break;
					case FSG_ERROR_HINT_OUTPUT_OPEN:
						printf("Unable to write fragment file.\n");
						break;
					case FSG_ERROR_HINT_OUTPUT_WRITE:
						printf("Unable to write fragment file.\n");
						break;
					default :
						printf("Unknown error occurred when trying spitting file to fragment files.\n");
						break;
				}
				return error;
			}
		}
		else if (mode == FSG_OPERATING_MODE_GATHER)
		{
			char* file_name = get_file_name(argc, argv);
			if (!file_name)
			{
				printf("Invalid parameters. No file output name specified.\n");
				print_instructions();
				return EINVAL;
			}
			char* fragment_name_prefix = get_fragment_name_prefix(argc, argv);
			if (!file_name)
			{
				printf("Invalid parameters. No fragment file name prefix specified.\n");
				print_instructions();
				return EINVAL;
			}
			uint32_t fragment_count;
			int error = count_fragments(fragment_name_prefix, &fragment_count);
			if (error)
			{
				switch (error)
				{
					case ENAMETOOLONG:
						printf("Invalid parameters. Fragment file name prefix is too long.\n");
						break;
					case ENOMEM:
						printf("Memory allocation failed.\n");
						break;
					case ERANGE:
						printf("Too many fragment files.\n");
						break;
					default:
						printf("Unknown error occurred when trying count the number fragment files.\n");
						break;
				}
				return error;
			}
			if (!fragment_count)
			{
				printf("No fragment files found with prefix \"%s\".\n", fragment_name_prefix);
				return ENOENT;
			}
			int error_hint;
			error = gather_fragments_to_file(FSG_DEFAULT_BUFFER_SIZE, file_name, fragment_name_prefix, fragment_count, &error_hint);
			if (!error)
				printf("Gather successful. %lu fragments gathered to file \"%s\"\n", fragment_count, file_name);
			else
			{
				switch (error_hint)
				{
				case FSG_ERROR_HINT_PARAMETER:
					printf("Invalid parameters.\n");
					print_instructions();
					break;
				case FSG_ERROR_HINT_MEMORY:
					printf("Memory allocation failed.\n");
					break;
				case FSG_ERROR_HINT_INPUT_OPEN:
					printf("Unable to read fragment file.\n");
					break;
				case FSG_ERROR_HINT_INPUT_READ:
					printf("Unable to read fragment file.\n");
					break;
				case FSG_ERROR_HINT_OUTPUT_OPEN:
					printf("Unable to write output file \"%s\".", file_name);
					break;
				case FSG_ERROR_HINT_OUTPUT_WRITE:
					printf("Unable to write output file \"%s\".", file_name);
					break;
				default:
					printf("Unknown error occurred when trying gather fragment files to single file.\n");
					break;
				}
				return error;
			}
		}
		else
			print_instructions();
	}
	else
		print_instructions();
	return 0;
}

void print_instructions()
{
	printf(
		"Program description:\n"
		"	This tool is used for splitting files in to smaller fragment files and reassembling the fragments back to the original file.\n"
		"Parameter List:\n"
		"	-h or --help Displays this message.\n"
		"	-m or --mode Specifies is program used to spit file to fragment files or gather fragment files to signle file. This value can split or s for slitting file to fragment files or gather or g for gathering fragment files to single file.\n"
		"	-s or --size Specifies size for fragment files. This argument is ignored when fragment files are gathered to single file.\n"
		"	-f or --file_name Specifies file that is split to fragment files or is gathered from fragment files.\n"
		"	-p or --fragment_prefix Specifies prefix part of the fragment file names. Fragment file names are prefix followed by fragment number and .dat file extension.\n");
}

int is_help_asked(int argc, char** argv)
{
	for (int i = 0; i != argc; ++i)
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help"))
			return 1;
	return 0;
}

int get_operating_mode(int argc, char** argv)
{
	int mode = FSG_OPERATING_MODE_UNKNOWN;
	if (argc)
		for (int i = 0, n = argc - 1; i != n; ++i)
			if (!strcmp(argv[i], "-m") || !strcmp(argv[i], "--mode"))
				if (mode == FSG_OPERATING_MODE_UNKNOWN)
				{
					if (!strcmp(argv[i + 1], "s") || !strcmp(argv[i + 1], "split"))
						mode = FSG_OPERATING_MODE_SPLIT;
					else if (!strcmp(argv[i + 1], "g") || !strcmp(argv[i + 1], "gather"))
						mode = FSG_OPERATING_MODE_GATHER;
					else
						mode = FSG_OPERATING_MODE_INVALID;
				}
				else
					mode = FSG_OPERATING_MODE_INVALID;
	return mode;
}

int get_fragment_size(int argc, char** argv, uint32_t* fragment_size)
{
	if (argc)
		for (int i = 0, n = argc - 1; i != n; ++i)
		{
			if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--size"))
			{
				char* read_size_string = argv[i + 1];
				uint32_t size = 0;
				for (char digit = *read_size_string++; digit; digit = *read_size_string++)
				{
					if (digit < '0' || digit > '9')
						return EINVAL;
					if (size != (((uint32_t)10 * size) / (uint32_t)10) || ((uint32_t)10 * size) > (((uint32_t)10 * size) + (uint32_t)(digit - '0')))
						return EINVAL;
					size = ((uint32_t)10 * size) + (uint32_t)(digit - '0');
				}
				if (i + 2 - argc)
				{
					uint32_t unit_shift = 0;
					if (!strcmp(argv[i + 2], "B"))
						unit_shift = 0;
					else if (!strcmp(argv[i + 2], "K") || !strcmp(argv[i + 2], "KB") || !strcmp(argv[i + 2], "KiB"))
						unit_shift = 10;
					else if(!strcmp(argv[i + 2], "M") || !strcmp(argv[i + 2], "MB") || !strcmp(argv[i + 2], "MiB"))
						unit_shift = 20;
					else if(!strcmp(argv[i + 2], "G") || !strcmp(argv[i + 2], "GB") || !strcmp(argv[i + 2], "GiB"))
						unit_shift = 30;
					if (size != ((size << unit_shift) >> unit_shift))
						return EINVAL;
					size <<= unit_shift;
				}
				*fragment_size = size;
				return 0;
			}
		}
	return EINVAL;
}

char* get_file_name(int argc, char** argv)
{
	int file_name_argument_index = -1;
	if (argc)
		for (int i = 0, n = argc - 1; i != n; ++i)
			if (!strcmp(argv[i], "-f") || !strcmp(argv[i], "--file_name"))
				if (file_name_argument_index == -1)
					file_name_argument_index = i + 1;
				else
					return 0;
	return file_name_argument_index != -1 ? argv[file_name_argument_index] : 0;
}

char* get_fragment_name_prefix(int argc, char** argv)
{
	int fragment_name_prefix_index = -1;
	if (argc)
		for (int i = 0, n = argc - 1; i != n; ++i)
			if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--fragment_prefix"))
				if (fragment_name_prefix_index == -1)
					fragment_name_prefix_index = i + 1;
				else
					return 0;
	return fragment_name_prefix_index != -1 ? argv[fragment_name_prefix_index] : 0;
}

int is_readable_file(const char* file_name)
{
	FILE* file = fopen(file_name, "rb");
	if (file)
	{
		fclose(file);
		return 1;
	}
	return 0;
}

int try_to_write_test_fragment(const char* fragment_name_prefix)
{
	size_t fragment_name_prefix_lenght = strlen(fragment_name_prefix);
	if (fragment_name_prefix_lenght > (fragment_name_prefix_lenght + (size_t)15) || (fragment_name_prefix_lenght + (size_t)15) != (((fragment_name_prefix_lenght + (size_t)15) * sizeof(char)) / sizeof(char)))
		return 0;
	char* fragment_name = (char*)malloc((fragment_name_prefix_lenght + (size_t)15) * sizeof(char));
	if (!fragment_name)
		return 0;
	write_fragment_file_name(fragment_name_prefix, fragment_name, 0xFFFFFFFF);
	FILE* file = fopen(fragment_name, "wb");
	if (file)
	{
		fclose(file);
		remove(fragment_name);
		free(fragment_name);
		return 1;
	}
	free(fragment_name);
	return 0;
}

int count_fragments(const char* fragment_name_prefix, uint32_t* fragment_count)
{
	size_t fragment_name_prefix_lenght = strlen(fragment_name_prefix);
	if (fragment_name_prefix_lenght > (fragment_name_prefix_lenght + (size_t)15) || (fragment_name_prefix_lenght + (size_t)15) != (((fragment_name_prefix_lenght + (size_t)15) * sizeof(char)) / sizeof(char)))
		return ENAMETOOLONG;
	char* fragment_name = (char*)malloc((fragment_name_prefix_lenght + (size_t)15) * sizeof(char));
	if (!fragment_name)
		return ENOMEM;
	uint32_t fragment_index = 0;
	for (int try_read_next = 1; try_read_next;)
	{
		if (fragment_index == (uint32_t)0xFFFFFFFF)
		{
			free(fragment_name);
			return ERANGE;
		}
		write_fragment_file_name(fragment_name_prefix, fragment_name, fragment_index);
		if (is_readable_file(fragment_name))
			++fragment_index;
		else
			try_read_next = 0;
	}
	free(fragment_name);
	*fragment_count = fragment_index;
	return 0;
}

void write_fragment_file_name(const char* fragment_name_prefix, char* file_name_buffer, uint32_t fragment_number)
{
	size_t prefix_lenght = strlen(fragment_name_prefix);
	memcpy(file_name_buffer, fragment_name_prefix, prefix_lenght);
	size_t length = 0;
	do
	{
		file_name_buffer[prefix_lenght + ((size_t)9 - length++)] = '0' + (char)(fragment_number % (uint32_t)10);
		fragment_number /= (uint32_t)10;
	} while (fragment_number);
	memmove(file_name_buffer + prefix_lenght, file_name_buffer + prefix_lenght + ((size_t)10 - length), length);
	memcpy(file_name_buffer + prefix_lenght + length, ".dat", 5);
}

int spit_file_to_fragments(size_t buffer_size, const char* file_name, const char* fragment_name_prefix, uint32_t fragment_size, uint32_t* fragment_count, int* error_hint)
{
	if (!buffer_size || !fragment_size)
	{
		*error_hint = FSG_ERROR_HINT_PARAMETER;
		return EINVAL;
	}
	size_t fragment_name_prefix_lenght = strlen(fragment_name_prefix);
	if (fragment_name_prefix_lenght > (fragment_name_prefix_lenght + (size_t)15) || (fragment_name_prefix_lenght + (size_t)15) != (((fragment_name_prefix_lenght + (size_t)15) * sizeof(char)) / sizeof(char)))
	{
		*error_hint = FSG_ERROR_HINT_PARAMETER;
		return ENAMETOOLONG;
	}
	char* fragment_name = (char*)malloc((fragment_name_prefix_lenght + (size_t)15) * sizeof(char));
	if (!fragment_name)
	{
		*error_hint = FSG_ERROR_HINT_MEMORY;
		return ENOMEM;
	}
	uintptr_t buffer = (uintptr_t)malloc(buffer_size);
	if (!buffer)
	{
		*error_hint = FSG_ERROR_HINT_MEMORY;
		free(fragment_name);
		return ENOMEM;
	}
	int error = 0;
	FILE* input_file = fopen(file_name, "rb");
	if (!input_file)
	{
		error = errno;
		*error_hint = FSG_ERROR_HINT_INPUT_OPEN;
		free((void*)buffer);
		free(fragment_name);
		return error;
	}
	FILE* fragment_file = 0;
	uint32_t fragment_written = 0;
	uint32_t fragment_index = 0;
	while (!error)
	{
		size_t file_data = fread((void*)buffer, 1, buffer_size, input_file);
		if (file_data)
		{
			for (size_t file_data_written = 0; !error && file_data_written != file_data;)
			{
				if (!fragment_file)
				{
					write_fragment_file_name(fragment_name_prefix, fragment_name, fragment_index);
					fragment_file = fopen(fragment_name, "wb");
					if (!fragment_file)
					{
						*error_hint = FSG_ERROR_HINT_OUTPUT_OPEN;
						error = errno;
					}
				}
				if (!error)
				{
					size_t write_size = file_data - file_data_written;
					if ((SIZE_MAX >= UINT32_MAX && write_size > (size_t)fragment_size) || (UINT32_MAX >= SIZE_MAX && (uint32_t)write_size > fragment_size))
						write_size = (size_t)fragment_size;
					if ((uint32_t)write_size > fragment_size - fragment_written)
						write_size = fragment_size - fragment_written;
					size_t write_result = fwrite((void*)(buffer + file_data_written), 1, write_size, fragment_file);
					if (write_result)
					{
						file_data_written += write_result;
						fragment_written += (uint32_t)write_result;
						if (fragment_written == fragment_size)
						{
							if (fflush(fragment_file) == EOF)
							{
								*error_hint = FSG_ERROR_HINT_OUTPUT_WRITE;
								error = ferror(fragment_file);
							}
							else
							{
								fclose(fragment_file);
								fragment_file = 0;
								fragment_written = 0;
								++fragment_index;
							}
						}
					}
					else
					{
						*error_hint = FSG_ERROR_HINT_OUTPUT_WRITE;
						error = ferror(fragment_file);
					}
				}
			}
		}
		else
		{
			error = ferror(input_file);
			if (!error)
			{
				if (feof(input_file))
				{
					if (fragment_file && fflush(fragment_file) == EOF)
					{
						*error_hint = FSG_ERROR_HINT_OUTPUT_WRITE;
						error = ferror(fragment_file);
					}
					else
						break;
				}
				else
				{
					*error_hint = FSG_ERROR_HINT_INPUT_READ;
					error = EIO;
				}
			}
			else
				*error_hint = FSG_ERROR_HINT_INPUT_READ;
		}
	}
	fclose(input_file);
	free((void*)buffer);
	if (error)
	{
		if (fragment_file)
		{
			fclose(fragment_file);
			remove(fragment_name);
		}
		while (fragment_index--)
		{
			write_fragment_file_name(fragment_name_prefix, fragment_name, fragment_index);
			remove(fragment_name);
		}
		free(fragment_name);
		return error;
	}
	if (fragment_file)
	{
		fclose(fragment_file);
		++fragment_index;
	}
	free(fragment_name);
	*fragment_count = fragment_index;
	*error_hint = FSG_ERROR_HINT_NONE;
	return 0;
}

int gather_fragments_to_file(size_t buffer_size, const char* file_name, const char* fragment_name_prefix, uint32_t fragment_count, int* error_hint)
{
	if (!buffer_size)
	{
		*error_hint = FSG_ERROR_HINT_PARAMETER;
		return EINVAL;
	}
	size_t fragment_name_prefix_lenght = strlen(fragment_name_prefix);
	if (fragment_name_prefix_lenght > (fragment_name_prefix_lenght + (size_t)15) || (fragment_name_prefix_lenght + (size_t)15) != (((fragment_name_prefix_lenght + (size_t)15) * sizeof(char)) / sizeof(char)))
	{
		*error_hint = FSG_ERROR_HINT_PARAMETER;
		return ENAMETOOLONG;
	}
	char* fragment_name = (char*)malloc((fragment_name_prefix_lenght + (size_t)15) * sizeof(char));
	if (!fragment_name)
	{
		*error_hint = FSG_ERROR_HINT_MEMORY;
		return ENOMEM;
	}
	uintptr_t buffer = (uintptr_t)malloc(buffer_size);
	if (!buffer)
	{
		free(fragment_name);
		*error_hint = FSG_ERROR_HINT_MEMORY;
		return ENOMEM;
	}
	int error = 0;
	FILE* output_file = fopen(file_name, "wb");
	if (!output_file)
	{
		error = errno;
		*error_hint = FSG_ERROR_HINT_OUTPUT_OPEN;
		free((void*)buffer);
		free(fragment_name);
		return error;
	}
	for (uint32_t fragment_index = 0; !error && fragment_index != fragment_count;)
	{
		write_fragment_file_name(fragment_name_prefix, fragment_name, fragment_index);
		FILE* fragment_file = fopen(fragment_name, "rb");
		if (fragment_file)
		{
			while (!error)
			{
				size_t file_data = fread((void*)buffer, 1, buffer_size, fragment_file);
				if (file_data)
				{
					for (size_t file_data_written = 0; !error && file_data_written != file_data;)
					{
						size_t write_result = fwrite((void*)(buffer + file_data_written), 1, file_data - file_data_written, output_file);
						if (write_result)
							file_data_written += write_result;
						else
						{
							*error_hint = FSG_ERROR_HINT_OUTPUT_WRITE;
							error = ferror(output_file);
						}
					}
				}
				else
				{
					error = ferror(fragment_file);
					if (!error)
					{
						if (feof(fragment_file))
							break;
						else
						{
							*error_hint = FSG_ERROR_HINT_INPUT_READ;
							error = EIO;
						}
					}
					else
						*error_hint = FSG_ERROR_HINT_INPUT_READ;
				}
			}
			fclose(fragment_file);
			if (!error)
				++fragment_index;
		}
		else
		{
			*error_hint = FSG_ERROR_HINT_INPUT_OPEN;
			error = errno;
		}
	}
	free((void*)buffer);
	free(fragment_name);
	if (error)
	{
		fclose(output_file);
		return error;
	}
	if (fflush(output_file) == EOF)
	{
		*error_hint = FSG_ERROR_HINT_OUTPUT_WRITE;
		error = ferror(output_file);
		fclose(output_file);
		return error;
	}
	*error_hint = FSG_ERROR_HINT_NONE;
	return 0;
}