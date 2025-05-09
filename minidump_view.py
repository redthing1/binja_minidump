# minidump_view.py
# a binaryview plugin for loading windows minidump files in binary ninja.
# this version uses the 'python-minidump' library (vendored).

import io
import traceback  # for detailed error logging
import datetime  # for timestamp conversion
from typing import Optional, Tuple  # for type hinting

# binary ninja api imports
from binaryninja import (
    BinaryView,
    SegmentFlag,
    SectionSemantics,
    Symbol,
    SymbolType,
    Platform,
    Architecture,
    Endianness,
    TagType,
    Logger,
)

# - python-minidump library integration
# it's vendored for maintainability
# import the main MinidumpFile class
from .lib.minidump.minidumpfile import MinidumpFile

# import specific stream classes and enums for type hinting and direct use
from .lib.minidump.streams import (
    MinidumpSystemInfo,
    MinidumpModuleList,
    MinidumpMemoryList,
    MinidumpMemory64List,
)
from .lib.minidump.streams import (
    MinidumpMemoryInfoList,
    MinidumpThreadList,
    ExceptionList,
)
from .lib.minidump.streams import (
    MinidumpUnloadedModuleList,
    MinidumpHandleDataStream,
    MinidumpMiscInfo,
)
from .lib.minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE
from .lib.minidump.streams.MemoryInfoListStream import (
    AllocationProtect,
)

# import common structs potentially needed
from .lib.minidump.common_structs import (
    MinidumpMemorySegment,
)


class MinidumpView(BinaryView):
    """
    binaryview for windows minidump files, using the python-minidump library.
    parses the dump, maps memory, identifies modules/threads, etc., adding
    annotations like comments, symbols, and tags where appropriate.
    """

    name = "Minidump"  # distinguish from other potential loaders
    long_name = "Windows Minidump"

    # tag type for marking the crash site
    CRASH_TAG_TYPE_NAME = "Crash Site"
    CRASH_TAG_ICON = "💥"

    # - registration and validation
    @classmethod
    def is_valid_for_data(cls, data: BinaryView) -> bool:
        """checks for the 'MDMP' signature at the beginning of the file."""
        if data.length < 4:
            return False
        magic = data.read(0, 4)
        is_mdmp = magic == b"MDMP"
        if is_mdmp:
            # use a logger instance for consistency, though Logger(0,...) is also functional
            # for class methods, a class-level logger could be defined if used more often
            Logger(0, cls.name).log_info("Valid MDMP signature found.")
        return is_mdmp

    def __init__(self, data: BinaryView):
        """initializes the view instance."""
        super().__init__(file_metadata=data.file, parent_view=data)
        # the raw file view provided by bn
        self.raw_data: BinaryView = data
        # tagged logger for this instance
        self.log: Logger = self.create_logger("Minidump")

        # this will hold the parsed minidump object from the library
        self.mdmp: Optional[MinidumpFile] = None

        # internal state populated during init
        # default, updated from systeminfo
        self._address_size: int = 8
        self._endianness: Endianness = Endianness.LittleEndian
        self._platform: Optional[Platform] = None
        self._arch: Optional[Architecture] = None
        self._crash_tag_type: Optional[TagType] = None
        # _min_virtual_address and _max_virtual_address are used to determine
        # a default entry point if no crash address is found.
        # bn will calculate its own view bounds based on added segments.
        self._min_virtual_address: int = 0xFFFFFFFFFFFFFFFF
        self._max_virtual_address: int = 0
        # track intended entry point, potentially set by exception stream
        self._entry_point_to_set: int = 0
        # cache memory protections (virtual_address -> AllocationProtect enum/int)
        self._memory_protections: dict = {}

    def init(self) -> bool:
        """
        main initialization method called by binary ninja.
        parses the minidump using the library and populates the view.
        """
        self.log.log_info(
            "Starting Minidump initialization using python-minidump library..."
        )

        # step 1: parse the minidump file using the library
        if not self._parse_minidump_with_library():
            # error logged within the helper method
            return False

        # step 2: create custom tag types
        self._crash_tag_type = self._get_or_create_tag_type(
            self.CRASH_TAG_TYPE_NAME, self.CRASH_TAG_ICON
        )

        # step 3: process the parsed streams in a logical order
        # system info is crucial for platform/architecture determination
        self._process_system_info()
        # memory info list provides protection flags for memory segments
        self._process_memory_info_list()
        # memory segments are mapped using add_auto_segment. this defines the address space for bn.
        self._process_memory_segments()
        # module list defines loaded modules as sections and symbols
        self._process_module_list()
        # log information about modules that were unloaded
        self._process_unloaded_module_list()
        # thread list adds information about threads, their stacks, and contexts
        self._process_thread_list()
        # exception stream identifies crash information and faulting address
        self._process_exception_stream()
        # handle data stream logs information about open handles
        self._process_handle_data_stream()
        # misc info logs process times, pid, etc.
        self._process_misc_info()

        # step 4: finalize bn view setup (sets the final entry point)
        self._finalize_view_setup()

        self.log.log_info("Minidump initialization complete.")
        return True

    # - helper methods for parsing and processing
    def _parse_minidump_with_library(self) -> bool:
        """helper: reads raw file data and parses it using the python-minidump library."""
        self.log.log_debug("Reading raw file data for python-minidump parsing...")
        try:
            file_bytes = self.raw_data.read(0, self.raw_data.length)
            file_like_object = io.BytesIO(file_bytes)
            # use the library's parse_buff method to parse the minidump from memory
            self.mdmp = MinidumpFile.parse_buff(file_like_object)
            self.log.log_info("python-minidump parsing successful.")
            if self.mdmp and self.mdmp.header:
                self.log.log_debug(
                    f"  Parsed Header: Streams={self.mdmp.header.NumberOfStreams}, Flags=0x{self.mdmp.header.Flags:016x}"
                )
            return True
        except Exception as e:
            self.log.log_error(f"python-minidump parsing failed: {e}")
            self.log.log_error(f"Traceback:\n{traceback.format_exc()}")
            self.mdmp = None  # ensure mdmp is None on failure
            return False

    def _process_system_info(self) -> None:
        """helper: processes systeminfo stream to set platform and architecture."""
        if not self.mdmp or not self.mdmp.sysinfo:
            self.log.log_warn(
                "SystemInfo stream not found or parsed by library. Platform/architecture defaults will be used."
            )
            return

        self.log.log_debug("Processing SystemInfo stream...")
        sys_info_stream = self.mdmp.sysinfo
        arch_str, os_str = self._map_system_info_to_platform(sys_info_stream)

        if arch_str and os_str:
            platform_name = f"{os_str}-{arch_str}"
            try:
                platform_obj = Platform[platform_name]
                self._platform = platform_obj
                self._arch = self._platform.arch
                if self._arch:
                    self._address_size = self._arch.address_size
                else:
                    # fallback if arch object doesn't provide address_size (should not happen for valid arch)
                    self._address_size = (
                        8 if "64" in arch_str or arch_str == "aarch64" else 4
                    )
                    self.log.log_warn(
                        f"Could not get address size from Architecture object for '{arch_str}', inferred {self._address_size}."
                    )

                # assign to the binaryview property to make it effective
                self.platform = self._platform
                self.log.log_info(
                    f"Platform set to '{self._platform.name}'. Address Size: {self._address_size} bytes."
                )
                # log additional system details
                self.log.log_info(
                    f"  OS Version: {sys_info_stream.MajorVersion}.{sys_info_stream.MinorVersion} Build {sys_info_stream.BuildNumber}"
                )
                if sys_info_stream.CSDVersion:  # CSDVersion might be empty
                    self.log.log_info(f"  Service Pack: {sys_info_stream.CSDVersion}")

            except KeyError:
                self.log.log_error(
                    f"Binary Ninja does not have a registered platform named '{platform_name}'. Analysis may be impaired."
                )
                self._platform = None  # ensure platform is not set
            except AttributeError as e:
                # this might occur if sys_info_stream is missing expected fields like MajorVersion
                self.log.log_error(
                    f"Error accessing attributes in SystemInfo stream (library structure mismatch?): {e}"
                )
            except Exception as e:
                self.log.log_error(
                    f"An unexpected error occurred while setting platform '{platform_name}': {e}"
                )
                self.log.log_error(f"Traceback:\n{traceback.format_exc()}")
                self._platform = None
        else:
            self.log.log_warn(
                "Could not determine a valid platform string from SystemInfo. Platform/architecture defaults will be used."
            )

    def _process_memory_info_list(self) -> None:
        """helper: processes memoryinfolist stream to cache memory region protections."""
        if (
            not self.mdmp
            or not self.mdmp.memory_info
            or not self.mdmp.memory_info.infos
        ):
            self.log.log_warn(
                "MemoryInfoList stream not found, not parsed, or empty. Segment permissions may be inaccurate."
            )
            return

        num_infos = len(self.mdmp.memory_info.infos)
        self.log.log_debug(
            f"Processing {num_infos} entries from MemoryInfoList stream..."
        )
        processed_count = 0
        for mem_info in self.mdmp.memory_info.infos:
            try:
                # cache protection flags (which can be an enum or int) by base address
                # mem_info.Protect is expected to be the AllocationProtect enum or its integer value
                self._memory_protections[mem_info.BaseAddress] = mem_info.Protect
                self.log.log_debug(
                    f"  MemInfo: VA=0x{mem_info.BaseAddress:x}, Size=0x{mem_info.RegionSize:x}, State={mem_info.State!r}, Protect={mem_info.Protect!r}, Type={mem_info.Type!r}"
                )
                processed_count += 1
            except AttributeError as e:
                self.log.log_error(
                    f"Error accessing attributes in a MINIDUMP_MEMORY_INFO entry (library structure mismatch?): {e}. Entry: {mem_info!r}"
                )
            except Exception as e:
                self.log.log_error(
                    f"Unexpected error processing a MINIDUMP_MEMORY_INFO entry: {e}. Entry: {mem_info!r}"
                )
                self.log.log_error(f"Traceback:\n{traceback.format_exc()}")

        self.log.log_info(
            f"Cached protection info for {processed_count}/{num_infos} memory regions."
        )

    def _process_memory_segments(self) -> None:
        """helper: processes memory64liststream or memoryliststream to map memory segments using add_auto_segment."""
        processed_any_segments = False
        processed_64bit_segments_successfully = False

        # prefer 64-bit memory list if available
        if (
            self.mdmp
            and self.mdmp.memory_segments_64
            and self.mdmp.memory_segments_64.memory_segments
        ):
            self.log.log_debug("Processing Memory64ListStream for memory segments...")
            try:
                # the python-minidump library pre-processes this into MinidumpMemorySegment objects
                for i, segment in enumerate(
                    self.mdmp.memory_segments_64.memory_segments
                ):
                    # robustly check for expected attributes from MinidumpMemorySegment
                    if (
                        not hasattr(segment, "start_virtual_address")
                        or segment.start_virtual_address is None
                    ):
                        self.log.log_error(
                            f"Skipping segment {i} in Memory64ListStream: Missing or None 'start_virtual_address'. Segment object: {segment!r}"
                        )
                        continue
                    if not hasattr(segment, "size") or segment.size is None:
                        self.log.log_error(
                            f"Skipping segment {i} in Memory64ListStream: Missing or None 'size'. Segment object: {segment!r}"
                        )
                        continue
                    if (
                        not hasattr(segment, "start_file_address")
                        or segment.start_file_address is None
                    ):
                        self.log.log_error(
                            f"Skipping segment {i} in Memory64ListStream: Missing or None 'start_file_address'. Segment object: {segment!r}"
                        )
                        continue

                    va = segment.start_virtual_address
                    size = segment.size
                    # the library provides start_file_address, which is the offset in the dump file
                    file_offset_in_dump = segment.start_file_address

                    if (
                        size == 0
                    ):  # segments with zero size in virtual address space are skipped
                        self.log.log_debug(
                            f"  Skipping zero-size segment {i} at VA 0x{va:x} (Memory64List)."
                        )
                        continue

                    self._update_virtual_address_extents(va, size)
                    protection_value = self._memory_protections.get(va)
                    r, w, x = self._translate_memory_protection_to_rwx(protection_value)
                    seg_flags_int = self._build_segment_flags_integer(r, w, x)

                    # data_length for add_auto_segment is how much of this segment is backed by file data.
                    # in minidumps, memory segments usually mean the data is present in the dump file.
                    # if the 'size' from minidump segment means virtual size, and 'file_offset_in_dump'
                    # points to 'size' bytes of data, then data_length is 'size'.
                    data_length_in_file = (
                        size  # assume segment content of 'size' is in the dump.
                    )

                    if seg_flags_int != 0:  # only add segments with some permissions
                        self.log.log_info(
                            f"  Adding segment {i} (Memory64List): VA=0x{va:0{self._address_size*2}x}, VirtSize=0x{size:x}, FileOffset=0x{file_offset_in_dump:x}, FileDataSize=0x{data_length_in_file:x}, Flags=0x{seg_flags_int:x} (R:{r},W:{w},X:{x})"
                        )
                        self.add_auto_segment(
                            va,
                            size,
                            file_offset_in_dump,
                            data_length_in_file,
                            seg_flags_int,
                        )
                        self._add_segment_comment(
                            va, protection_value, r, w, x, "Memory64ListStream"
                        )
                        processed_any_segments = True
                    else:
                        # this handles PAGE_NOACCESS or other zero-permission cases
                        self.log.log_warn(
                            f"  Skipping segment {i} (Memory64List) at VA=0x{va:0{self._address_size*2}x} due to zero permissions (Original Protection: {protection_value!r})."
                        )
                processed_64bit_segments_successfully = True
            except Exception as e:
                self.log.log_error(
                    f"Unexpected error during Memory64ListStream processing: {e}"
                )
                self.log.log_error(f"Traceback:\n{traceback.format_exc()}")
                # ensure fallback to 32-bit list if 64-bit processing encounters an unexpected error
                processed_64bit_segments_successfully = False

        # fallback to 32-bit list if 64-bit list was not present, empty, or failed processing
        if (
            not processed_64bit_segments_successfully
            and self.mdmp
            and self.mdmp.memory_segments
            and self.mdmp.memory_segments.memory_segments
        ):
            self.log.log_debug(
                "Processing MemoryListStream for memory segments (fallback or primary for 32-bit dumps)..."
            )
            try:
                for i, segment in enumerate(self.mdmp.memory_segments.memory_segments):
                    if (
                        not hasattr(segment, "start_virtual_address")
                        or segment.start_virtual_address is None
                    ):
                        self.log.log_error(
                            f"Skipping segment {i} in MemoryListStream: Missing or None 'start_virtual_address'. Segment object: {segment!r}"
                        )
                        continue
                    if not hasattr(segment, "size") or segment.size is None:
                        self.log.log_error(
                            f"Skipping segment {i} in MemoryListStream: Missing or None 'size'. Segment object: {segment!r}"
                        )
                        continue
                    if (
                        not hasattr(segment, "start_file_address")
                        or segment.start_file_address is None
                    ):
                        self.log.log_error(
                            f"Skipping segment {i} in MemoryListStream: Missing or None 'start_file_address'. Segment object: {segment!r}"
                        )
                        continue

                    va = segment.start_virtual_address
                    size = segment.size
                    file_offset_in_dump = segment.start_file_address
                    data_length_in_file = size

                    if size == 0:
                        self.log.log_debug(
                            f"  Skipping zero-size segment {i} at VA 0x{va:x} (MemoryList)."
                        )
                        continue

                    self._update_virtual_address_extents(va, size)
                    protection_value = self._memory_protections.get(va)
                    r, w, x = self._translate_memory_protection_to_rwx(protection_value)
                    seg_flags_int = self._build_segment_flags_integer(r, w, x)

                    if seg_flags_int != 0:
                        self.log.log_info(
                            f"  Adding segment {i} (MemoryList): VA=0x{va:0{self._address_size*2}x}, VirtSize=0x{size:x}, FileOffset=0x{file_offset_in_dump:x}, FileDataSize=0x{data_length_in_file:x}, Flags=0x{seg_flags_int:x} (R:{r},W:{w},X:{x})"
                        )
                        self.add_auto_segment(
                            va,
                            size,
                            file_offset_in_dump,
                            data_length_in_file,
                            seg_flags_int,
                        )
                        self._add_segment_comment(
                            va, protection_value, r, w, x, "MemoryListStream"
                        )
                        processed_any_segments = True
                    else:
                        self.log.log_warn(
                            f"  Skipping segment {i} (MemoryList) at VA=0x{va:0{self._address_size*2}x} due to zero permissions (Original Protection: {protection_value!r})."
                        )
            except Exception as e:
                self.log.log_error(
                    f"Unexpected error during MemoryListStream processing: {e}"
                )
                self.log.log_error(f"Traceback:\n{traceback.format_exc()}")

        if not processed_any_segments:
            self.log.log_warn(
                "No memory segments could be successfully processed from either Memory64ListStream or MemoryListStream. The memory map will be empty or incomplete."
            )

    def _update_virtual_address_extents(self, va: int, size: int) -> None:
        """
        helper: updates the overall min/max virtual addresses encountered.
        this is used for determining a fallback entry point.
        binary ninja will determine its own view bounds from added segments.
        """
        if size <= 0:  # ensure size is positive before updating extents
            return
        self._min_virtual_address = min(self._min_virtual_address, va)
        self._max_virtual_address = max(self._max_virtual_address, va + size)

    def _build_segment_flags_integer(self, r: bool, w: bool, x: bool) -> int:
        """
        helper: constructs an integer representing combined segment flags for binary ninja.
        returns 0 if no permissions (r,w,x) are set.
        """
        flags_val = 0
        if r:
            flags_val |= SegmentFlag.SegmentReadable.value
        if w:
            flags_val |= SegmentFlag.SegmentWritable.value
        if x:
            flags_val |= SegmentFlag.SegmentExecutable.value

        # add hints for content type based on permissions
        if x:  # if executable, it contains code
            flags_val |= SegmentFlag.SegmentContainsCode.value
        elif (
            r or w
        ):  # if readable or writable but not executable, assume it contains data
            flags_val |= SegmentFlag.SegmentContainsData.value
        # if no r,w,x, it might be a reserved but inaccessible segment; flags_val remains 0

        return flags_val

    def _add_segment_comment(
        self,
        va: int,
        original_protection_value,  # can be enum, int, or None
        r: bool,
        w: bool,
        x: bool,
        stream_name: str,
    ) -> None:
        """helper: adds a descriptive comment to a newly added segment's start address."""
        protection_str = "Unknown (MemoryInfoList missing or incomplete for this VA)"
        if original_protection_value is not None:
            if hasattr(original_protection_value, "name"):  # for enum types
                protection_str = original_protection_value.name
            else:  # for int or other types
                protection_str = (
                    f"0x{int(original_protection_value):x}"
                    if isinstance(original_protection_value, int)
                    else str(original_protection_value)
                )

        self.set_comment_at(
            va,
            f"Minidump Memory Segment (from {stream_name})\n"
            f"Original Protection: {protection_str}\n"
            f"Mapped Permissions: R={'Yes' if r else 'No'}, W={'Yes' if w else 'No'}, X={'Yes' if x else 'No'}",
        )

    def _process_module_list(self) -> None:
        """helper: processes modulelist stream to define sections and symbols for loaded modules."""
        if not self.mdmp or not self.mdmp.modules or not self.mdmp.modules.modules:
            self.log.log_warn(
                "ModuleList stream not found, not parsed, or empty. No modules will be defined."
            )
            return

        num_modules = len(self.mdmp.modules.modules)
        self.log.log_info(f"Processing {num_modules} modules from ModuleListStream.")
        processed_count = 0
        for i, mod_entry in enumerate(self.mdmp.modules.modules):
            try:
                # robustly check for essential attributes
                if (
                    not hasattr(mod_entry, "name")
                    or not hasattr(mod_entry, "baseaddress")
                    or not hasattr(mod_entry, "size")
                ):
                    self.log.log_error(
                        f"Skipping module entry {i} due to missing essential attributes (name, baseaddress, or size). Module object: {mod_entry!r}"
                    )
                    continue

                module_name_from_dump = mod_entry.name
                base_va = mod_entry.baseaddress
                size = mod_entry.size

                # further validation of critical values
                if base_va is None or size is None:
                    self.log.log_error(
                        f"Skipping module entry {i} ('{module_name_from_dump or 'N/A'}') due to None base address or size: Base=0x{base_va:x if base_va is not None else 'None'}, Size=0x{size:x if size is not None else 'None'}"
                    )
                    continue
                if size <= 0:
                    self.log.log_warn(
                        f"  Skipping module {i} ('{module_name_from_dump or f'UnknownModule_0x{base_va:x}'}') due to zero or negative size: {size}"
                    )
                    continue

                # ensure a valid name for the section and symbol
                module_name_final = (
                    module_name_from_dump
                    if module_name_from_dump
                    else f"UnknownModule_0x{base_va:x}"
                )
                # ensure the symbol name is a string
                symbol_name_str = str(module_name_final)

                self.log.log_info(
                    f"  Adding module {i}: {symbol_name_str}, BaseVA=0x{base_va:0{self._address_size*2}x}, Size=0x{size:x}"
                )
                # add a section for the module's memory region.
                # sections describe semantic regions within segments.
                # assuming modules contain mostly code, but could be refined if RTTI or other info is available.
                self.add_auto_section(
                    symbol_name_str,
                    base_va,
                    size,
                    SectionSemantics.ReadOnlyCodeSectionSemantics,
                )
                # define a symbol for the module base
                # SymbolType.LibraryFunctionSymbol is often used for module bases or imported library functions.
                self.define_auto_symbol(
                    Symbol(SymbolType.LibraryFunctionSymbol, base_va, symbol_name_str)
                )

                timestamp_val = getattr(mod_entry, "timestamp", "N/A")
                checksum_val = getattr(mod_entry, "checksum", "N/A")
                timestamp_str = "N/A"
                if isinstance(timestamp_val, int):
                    try:
                        # assume utc if timezone is not part of the dump's timestamp format
                        timestamp_dt = datetime.datetime.fromtimestamp(
                            timestamp_val, tz=datetime.timezone.utc
                        )
                        timestamp_str = timestamp_dt.isoformat()
                    except (
                        ValueError,
                        OSError,
                        TypeError,
                    ) as ts_ex:  # catch potential errors fromtimestamp
                        timestamp_str = (
                            f"Invalid raw timestamp 0x{timestamp_val:x} ({ts_ex})"
                        )
                elif timestamp_val != "N/A":
                    timestamp_str = str(timestamp_val)

                checksum_str = (
                    f"0x{checksum_val:x}"
                    if isinstance(checksum_val, int)
                    else str(checksum_val)
                )

                self.set_comment_at(
                    base_va,
                    f"Module: {symbol_name_str}\n"
                    f"Base Address: 0x{base_va:x}\n"
                    f"Size: 0x{size:x}\n"
                    f"Timestamp: {timestamp_str} (Raw: {timestamp_val!r})\n"
                    f"Checksum: {checksum_str}",
                )
                processed_count += 1

            except AttributeError as e:  # if other less critical attributes are missing
                self.log.log_warn(
                    f"Error accessing attributes for module entry {i} (library structure mismatch or partial data?): {e}. Module object: {mod_entry!r}"
                )
            except Exception as e:  # catch any other unexpected errors for this module
                self.log.log_error(
                    f"Unexpected error processing module entry {i} ('{getattr(mod_entry, 'name', 'N/A')}'): {e}"
                )
                self.log.log_error(f"Traceback:\n{traceback.format_exc()}")
                # continue to the next module
        self.log.log_info(
            f"Successfully processed {processed_count}/{num_modules} module entries."
        )

    def _process_thread_list(self) -> None:
        """helper: processes threadlist stream for thread info, stacks, and contexts."""
        if not self.mdmp or not self.mdmp.threads or not self.mdmp.threads.threads:
            self.log.log_warn(
                "ThreadList stream not found, not parsed, or empty. No threads will be defined."
            )
            return

        num_threads = len(self.mdmp.threads.threads)
        self.log.log_info(f"Processing {num_threads} threads from ThreadListStream.")
        processed_count = 0
        for i, thread_entry in enumerate(self.mdmp.threads.threads):
            try:
                # check for essential attributes before trying to access them
                # these checks are for MINIDUMP_THREAD and its nested structures
                if not all(
                    hasattr(thread_entry, attr)
                    for attr in ["ThreadId", "Stack", "Teb", "ThreadContext"]
                ):
                    self.log.log_error(
                        f"Skipping thread entry {i}: Missing top-level attributes (ThreadId, Stack, Teb, or ThreadContext). Thread object: {thread_entry!r}"
                    )
                    continue
                if not all(
                    hasattr(thread_entry.Stack, attr)
                    for attr in ["StartOfMemoryRange", "MemoryLocation"]
                ):
                    self.log.log_error(
                        f"Skipping thread entry {i} (ID: {thread_entry.ThreadId}): Missing Stack attributes. Stack object: {thread_entry.Stack!r}"
                    )
                    continue
                if not hasattr(thread_entry.Stack.MemoryLocation, "DataSize"):
                    self.log.log_error(
                        f"Skipping thread entry {i} (ID: {thread_entry.ThreadId}): Missing Stack.MemoryLocation.DataSize. Location object: {thread_entry.Stack.MemoryLocation!r}"
                    )
                    continue

                tid = thread_entry.ThreadId
                stack_va = thread_entry.Stack.StartOfMemoryRange
                # corrected access path for stack size based on common_structs.py (MemoryLocation.DataSize for the actual memory dump size)
                stack_size = thread_entry.Stack.MemoryLocation.DataSize
                teb = thread_entry.Teb

                self.log.log_info(
                    f"  Thread ID: {tid}, Stack Start: 0x{stack_va:x}, Stack Size: 0x{stack_size:x}, TEB: 0x{teb:x}"
                )

                if (
                    stack_va is not None and stack_size > 0
                ):  # only add stack comment/symbol if valid
                    # stack regions are usually part of segments already added by _process_memory_segments.
                    # here we are just adding semantic information (comments, symbols).
                    self.set_comment_at(
                        stack_va,
                        f"Thread {tid} Stack\n"
                        f"Base: 0x{stack_va:x}\n"
                        f"Size: 0x{stack_size:x}\n"
                        f"TEB: 0x{teb:x}",
                    )
                    self.define_auto_symbol(
                        Symbol(
                            SymbolType.DataSymbol, stack_va, f"Thread_{tid}_StackBase"
                        )
                    )
                else:
                    self.log.log_warn(
                        f"  Thread ID: {tid} has invalid stack info (VA: {stack_va}, Size: {stack_size}). Skipping stack symbol/comment."
                    )

                # add symbol for TEB if it's within mapped memory (optional check)
                if teb is not None and self.get_segment_at(
                    teb
                ):  # get_segment_at checks if TEB is in a known segment
                    self.define_auto_symbol(
                        Symbol(SymbolType.DataSymbol, teb, f"Thread_{tid}_TEB")
                    )

                # ThreadContext is a MINIDUMP_LOCATION_DESCRIPTOR
                context_loc = thread_entry.ThreadContext
                self.log.log_debug(
                    f"    Thread {tid} context location in dump: RVA=0x{context_loc.Rva:x}, Size=0x{context_loc.DataSize:x}"
                )
                # The actual thread context data is at context_loc.Rva in the dump file.
                # This data needs to be read from self.raw_data (parent view) and parsed based on architecture.
                # This plugin does not currently parse the register values from the context.
                self.log.log_warn(
                    f"    Thread {tid}: Detailed context parsing (registers) from RVA 0x{context_loc.Rva:x} is not implemented. This would require manual parsing of the raw context data based on architecture."
                )
                processed_count += 1

            except AttributeError as e:
                self.log.log_warn(
                    f"Error accessing attributes for thread entry {i} (library structure mismatch or partial data?): {e}. Thread object: {thread_entry!r}"
                )
            except Exception as e:
                self.log.log_error(
                    f"Unexpected error processing thread entry {i} (ID: {getattr(thread_entry, 'ThreadId', 'N/A')}): {e}"
                )
                self.log.log_error(f"Traceback:\n{traceback.format_exc()}")
                # continue to the next thread
        self.log.log_info(
            f"Successfully processed {processed_count}/{num_threads} thread entries."
        )

    def _process_exception_stream(self) -> None:
        """helper: processes the exception stream, if present, to mark crash site."""
        if (
            not self.mdmp
            or not self.mdmp.exception
            or not self.mdmp.exception.exception_records  # this is a list
            or not self.mdmp.exception.exception_records[
                0
            ]  # ensure at least one record
        ):
            self.log.log_debug(
                "No ExceptionStream found, no records, or first record is invalid (dump may not be from a crash)."
            )
            return

        num_records = len(self.mdmp.exception.exception_records)
        self.log.log_info(
            f"Processing {num_records} exception record(s) from ExceptionStream..."
        )

        try:
            # typically, the first exception record is the most relevant
            primary_exception_info = self.mdmp.exception.exception_records[0]
            # primary_exception_info is MINIDUMP_EXCEPTION_STREAM -> .exception_records list of MINIDUMP_EXCEPTION_RECORD
            # the library structure is MinidumpExceptionStream -> .exception_records (list of MinidumpException)
            # then MinidumpException -> .ExceptionRecord (the actual record struct), .ThreadId
            actual_exception_record = primary_exception_info.ExceptionRecord
            thread_id = primary_exception_info.ThreadId
            exc_addr = actual_exception_record.ExceptionAddress
            # ExceptionCode_raw is preferred as ExceptionCode might be an enum
            exc_code_val = actual_exception_record.ExceptionCode_raw
            exc_flags_val = actual_exception_record.ExceptionFlags

            exc_code_str = self._map_exception_code_to_string(exc_code_val)

            self.log.log_warn(f"  PRIMARY EXCEPTION Occurred in Thread ID: {thread_id}")
            self.log.log_warn(f"  Exception Code: 0x{exc_code_val:X} ({exc_code_str})")
            self.log.log_warn(f"  Exception Flags: 0x{exc_flags_val:X}")
            self.log.log_warn(
                f"  Exception Address (Faulting IP): 0x{exc_addr:0{self._address_size*2}x}"
            )

            comment_lines = [
                "== MINIDUMP CRASH SITE ==",
                f"Thread ID: {thread_id}",
                f"Exception Code: 0x{exc_code_val:X} ({exc_code_str})",
                f"Faulting Address: 0x{exc_addr:0{self._address_size*2}x}",
            ]

            if (
                hasattr(actual_exception_record, "ExceptionInformation")
                and actual_exception_record.NumberParameters > 0
            ):
                # ensure we don't read past available parameters
                num_params_to_show = min(
                    actual_exception_record.NumberParameters,
                    len(actual_exception_record.ExceptionInformation),
                )
                params_to_show = actual_exception_record.ExceptionInformation[
                    :num_params_to_show
                ]
                params_str = ", ".join([f"0x{p:x}" for p in params_to_show])
                comment_lines.append(f"Exception Parameters: [{params_str}]")
                self.log.log_warn(f"  Exception Parameters: [{params_str}]")

            self.set_comment_at(exc_addr, "\n".join(comment_lines))

            if self._crash_tag_type:
                self.add_tag(exc_addr, self._crash_tag_type, f"Crash: {exc_code_str}")

            self.log.log_info(
                f"Setting intended entry point to primary exception address 0x{exc_addr:x}"
            )
            # store the intended entry point; will be set in _finalize_view_setup
            self._entry_point_to_set = exc_addr

        except AttributeError as e:
            self.log.log_error(
                f"Error accessing attributes in ExceptionStream data (library structure mismatch or malformed data?): {e}"
            )
            self.log.log_error(f"Traceback:\n{traceback.format_exc()}")
        except IndexError:
            self.log.log_error(
                "Error processing ExceptionStream: No exception records found in the list, though the list itself was present."
            )
        except Exception as e:
            self.log.log_error(f"Unexpected error processing ExceptionStream: {e}")
            self.log.log_error(f"Traceback:\n{traceback.format_exc()}")

    def _map_exception_code_to_string(self, code: int) -> str:
        """helper: maps common windows exception codes to human-readable strings."""
        # refer to ntstatus.h or winnt.h for more comprehensive lists
        common_codes = {
            0x80000003: "Breakpoint (STATUS_BREAKPOINT)",
            0xC0000005: "Access Violation (STATUS_ACCESS_VIOLATION)",
            0xC0000006: "In Page Error (STATUS_IN_PAGE_ERROR)",
            0xC0000017: "No Memory (STATUS_NO_MEMORY)",
            0xC000001D: "Illegal Instruction (STATUS_ILLEGAL_INSTRUCTION)",
            0xC0000094: "Integer Divide by Zero (STATUS_INTEGER_DIVIDE_BY_ZERO)",
            0xC0000096: "Privileged Instruction (STATUS_PRIVILEGED_INSTRUCTION)",
            0xC00000FD: "Stack Overflow (STATUS_STACK_OVERFLOW)",
            0xC0000135: "DLL Not Found (STATUS_DLL_NOT_FOUND)",
            0xC0000409: "Stack Buffer Overrun (STATUS_STACK_BUFFER_OVERRUN / FASTFAIL_STACK_COOKIE_CHECK_FAILURE)",
            0xC0000420: "Assertion Failure (STATUS_ASSERTION_FAILURE)",
        }
        return common_codes.get(code, f"Unknown (0x{code:X})")

    def _process_unloaded_module_list(self) -> None:
        """helper: logs information about unloaded modules from the UnloadedModuleList stream."""
        if (
            not self.mdmp
            or not self.mdmp.unloaded_modules
            or not self.mdmp.unloaded_modules.modules
        ):
            self.log.log_debug(
                "No UnloadedModuleList stream found, not parsed, or empty."
            )
            return

        num_unloaded = len(self.mdmp.unloaded_modules.modules)
        self.log.log_info(
            f"Processing {num_unloaded} unloaded modules from UnloadedModuleListStream."
        )
        for i, mod_entry in enumerate(self.mdmp.unloaded_modules.modules):
            try:
                # use getattr for robustness as these are just for logging
                name = getattr(
                    mod_entry,
                    "name",
                    f"UnknownUnloaded_0x{getattr(mod_entry, 'baseaddress', 0):x}",
                )
                base_addr = getattr(mod_entry, "baseaddress", "N/A")
                size = getattr(mod_entry, "size", "N/A")
                timestamp = getattr(mod_entry, "timestamp", "N/A")

                base_addr_str = (
                    f"0x{base_addr:x}" if isinstance(base_addr, int) else str(base_addr)
                )
                size_str = f"0x{size:x}" if isinstance(size, int) else str(size)
                timestamp_str = (
                    f"0x{timestamp:x}" if isinstance(timestamp, int) else str(timestamp)
                )

                self.log.log_info(
                    f"  Unloaded Module {i}: {name}, Base: {base_addr_str}, Size: {size_str}, Timestamp: {timestamp_str}"
                )
            except (
                Exception
            ) as e:  # catch any unexpected error during logging this entry
                self.log.log_warn(
                    f"Could not fully log an unloaded module entry {i} (data issue or unexpected error): {e}. Entry: {mod_entry!r}"
                )

    def _process_handle_data_stream(self) -> None:
        """helper: logs basic information about open handles from the HandleDataStream."""
        if not self.mdmp or not self.mdmp.handles or not self.mdmp.handles.handles:
            self.log.log_debug("No HandleDataStream found, not parsed, or empty.")
            return

        num_handles = len(self.mdmp.handles.handles)
        self.log.log_info(f"Processing {num_handles} handles from HandleDataStream.")
        for i, handle_entry in enumerate(self.mdmp.handles.handles):
            try:
                # use getattr for robustness as these are just for logging
                handle_value = getattr(handle_entry, "Handle", "N/A")
                type_name = getattr(handle_entry, "TypeName", "N/A")
                object_name = getattr(handle_entry, "ObjectName", "N/A")
                attributes = getattr(handle_entry, "Attributes", "N/A")

                handle_value_str = (
                    f"0x{handle_value:x}"
                    if isinstance(handle_value, int)
                    else str(handle_value)
                )
                attributes_str = (
                    f"0x{attributes:x}"
                    if isinstance(attributes, int)
                    else str(attributes)
                )

                self.log.log_debug(  # often too verbose for info, use debug
                    f"  Handle {i}: Value={handle_value_str}, Type='{type_name}', Name='{object_name}', Attributes={attributes_str}"
                )
            except Exception as e:
                self.log.log_warn(
                    f"Could not fully log handle entry {i} (data issue or unexpected error): {e}. Entry: {handle_entry!r}"
                )

    def _process_misc_info(self) -> None:
        """helper: logs miscellaneous process information from the MiscInfo stream."""
        if not self.mdmp or not self.mdmp.misc_info:
            self.log.log_debug("No MiscInfo stream found or not parsed.")
            return

        self.log.log_info("Processing MiscInfoStream...")
        misc_info_stream = self.mdmp.misc_info
        try:
            # processid is often present
            if (
                hasattr(misc_info_stream, "ProcessId")
                and misc_info_stream.ProcessId is not None
            ):
                self.log.log_info(f"  Process ID (PID): {misc_info_stream.ProcessId}")

            # process times
            if (
                hasattr(misc_info_stream, "ProcessCreateTime")
                and misc_info_stream.ProcessCreateTime is not None
            ):
                create_time_raw = misc_info_stream.ProcessCreateTime
                create_time_str = f"Raw value 0x{create_time_raw:x}"
                try:
                    # minidump processcreate_time is a windows filetime-like unixtime
                    create_time_dt = datetime.datetime.fromtimestamp(
                        create_time_raw, tz=datetime.timezone.utc
                    )
                    create_time_str = create_time_dt.isoformat()
                except (ValueError, OSError, TypeError) as ts_ex:
                    create_time_str = (
                        f"Invalid raw timestamp 0x{create_time_raw:x} ({ts_ex})"
                    )
                self.log.log_info(f"  Process Create Time: {create_time_str}")

            if (
                hasattr(misc_info_stream, "ProcessUserTime")
                and misc_info_stream.ProcessUserTime is not None
            ):
                self.log.log_info(
                    f"  Process User Time (seconds): {misc_info_stream.ProcessUserTime}"
                )
            if (
                hasattr(misc_info_stream, "ProcessKernelTime")
                and misc_info_stream.ProcessKernelTime is not None
            ):
                self.log.log_info(
                    f"  Process Kernel Time (seconds): {misc_info_stream.ProcessKernelTime}"
                )

            # cpu information (availability depends on MiscInfoFlags)
            if (
                hasattr(misc_info_stream, "ProcessorMaxMhz")
                and misc_info_stream.ProcessorMaxMhz is not None
            ):
                self.log.log_info(f"  CPU Max MHz: {misc_info_stream.ProcessorMaxMhz}")
            if (
                hasattr(misc_info_stream, "ProcessorCurrentMhz")
                and misc_info_stream.ProcessorCurrentMhz is not None
            ):
                self.log.log_info(
                    f"  CPU Current MHz: {misc_info_stream.ProcessorCurrentMhz}"
                )

        except (
            AttributeError
        ) as e:  # should be caught by hasattr mostly, but as a fallback
            self.log.log_warn(
                f"Could not fully parse MiscInfoStream due to missing attributes (library structure mismatch?): {e}"
            )
        except Exception as e:
            self.log.log_error(f"Unexpected error processing MiscInfoStream: {e}")
            self.log.log_error(f"Traceback:\n{traceback.format_exc()}")

    def _finalize_view_setup(self) -> None:
        """helper: performs final setup steps, like setting the default entry point."""
        # if the exception stream didn't set a specific entry point (e.g., crash address),
        # and we have a valid minimum virtual address from mapped segments, use that.
        # otherwise, entry point remains 0, which is a common default.
        if self._entry_point_to_set == 0:
            if (
                self._min_virtual_address != 0xFFFFFFFFFFFFFFFF
                and self._min_virtual_address != 0
            ):
                self.log.log_info(
                    f"No specific entry point (e.g., crash address) found. Setting entry point to minimum mapped virtual address: 0x{self._min_virtual_address:x}"
                )
                self._entry_point_to_set = self._min_virtual_address
            else:
                self.log.log_info(
                    "No specific entry point found and no valid minimum virtual address. Entry point will default to 0x0."
                )
        else:
            self.log.log_info(
                f"Entry point previously set (likely crash address): 0x{self._entry_point_to_set:x}"
            )

        # use the binaryview api to add the determined entry point
        # this also influences where binary ninja initially navigates
        self.add_entry_point(self._entry_point_to_set)
        self.log.log_info(
            f"Final view entry point set to 0x{self._entry_point_to_set:x}."
        )
        self.log.log_info("Binary Ninja view setup finalized. Ready for analysis.")

    def _get_or_create_tag_type(self, name: str, icon: str) -> Optional[TagType]:
        """
        helper: gets an existing tag type or creates it if it doesn't exist.
        caches the result in self._crash_tag_type for its specific use case.
        returns the tagtype object or none if creation/retrieval fails.
        """
        try:
            # first, try to get an existing tag type
            tag_type = self.get_tag_type(name)
            if tag_type:
                self.log.log_debug(f"Found existing TagType '{name}'.")
                return tag_type
        except KeyError:
            # keyerror means the tag type does not exist, so we proceed to create it
            self.log.log_debug(f"TagType '{name}' not found, attempting creation.")
        except Exception as e:
            # other unexpected errors during get_tag_type
            self.log.log_warn(
                f"Error while trying to get TagType '{name}': {e}. Will attempt creation."
            )

        try:
            # if not found or error during get, try to create it
            self.log.log_info(f"Creating new TagType '{name}' with icon '{icon}'.")
            new_tag_type = self.create_tag_type(name, icon)
            return new_tag_type
        except Exception as e:
            self.log.log_error(
                f"Failed to create TagType '{name}': {e}. Tagging for this type will be disabled."
            )
            # as a last resort, try to get it again in case of a race condition (unlikely here but safe)
            try:
                return self.get_tag_type(name)
            except Exception:
                self.log.log_error(
                    f"Still failed to get or create TagType '{name}' after creation attempt."
                )
                return None

    def _map_system_info_to_platform(
        self, sys_info_stream: MinidumpSystemInfo
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        helper: maps minidump system info (specifically processor architecture)
        to binary ninja platform and architecture strings.
        returns a tuple (arch_string, os_string). os_string is typically 'windows'.
        """
        arch_str: Optional[str] = None
        os_str: Optional[str] = "windows"  # minidumps are windows-specific

        try:
            # PROCESSOR_ARCHITECTURE is an enum from the minidump library
            cpu_arch_enum_val = sys_info_stream.ProcessorArchitecture

            if cpu_arch_enum_val == PROCESSOR_ARCHITECTURE.AMD64:
                arch_str = "x86_64"
            elif cpu_arch_enum_val == PROCESSOR_ARCHITECTURE.INTEL:
                arch_str = "x86"  # for 32-bit x86
            elif cpu_arch_enum_val == PROCESSOR_ARCHITECTURE.ARM:
                arch_str = "armv7"  # common default for 32-bit arm
            elif cpu_arch_enum_val == PROCESSOR_ARCHITECTURE.IA64:  # intel itanium
                arch_str = "ia64"  # bn may or may not have this explicitly
                self.log.log_warn(
                    "IA64 architecture detected. Binary Ninja support may vary."
                )
            elif cpu_arch_enum_val == PROCESSOR_ARCHITECTURE.AARCH64:  # arm64
                arch_str = "aarch64"
            elif cpu_arch_enum_val == PROCESSOR_ARCHITECTURE.UNKNOWN:
                self.log.log_warn(
                    "Processor architecture reported as UNKNOWN in SystemInfo."
                )
                return None, os_str  # os_str is still windows
            else:
                self.log.log_warn(
                    f"Unrecognized processor architecture enum value from SystemInfo: {cpu_arch_enum_val!r}. Cannot map to BN architecture."
                )
                return None, os_str
            return arch_str, os_str

        except AttributeError as e:
            self.log.log_error(
                f"Error accessing ProcessorArchitecture in SystemInfo stream (library structure mismatch?): {e}"
            )
            return None, None  # critical failure to determine arch
        except Exception as e:
            self.log.log_error(f"Unexpected error mapping system info to platform: {e}")
            self.log.log_error(f"Traceback:\n{traceback.format_exc()}")
            return None, None

    def _translate_memory_protection_to_rwx(
        self, protection_value  # can be AllocationProtect enum, int, or None
    ) -> Tuple[bool, bool, bool]:
        """
        helper: translates minidump memory protection flags (windows PAGE_ constants)
        to a tuple of (read, write, execute) booleans.
        """
        # default to readable and executable if protection info is missing, a common scenario for some dumps/regions
        # or adjust this default if a more restrictive stance (e.g., no access) is preferred for unknown protections
        if protection_value is None:
            self.log.log_debug(
                "Protection value is None, defaulting to R-X permissions."
            )
            return True, False, True

        r, w, x = False, False, False
        current_flags_int: int

        if isinstance(protection_value, AllocationProtect):
            # if it's the enum, get its integer value
            current_flags_int = protection_value.value
        elif isinstance(protection_value, int):
            current_flags_int = protection_value
        else:
            self.log.log_warn(
                f"Unknown memory protection flag type: {protection_value!r}. Defaulting to R-X permissions."
            )
            return True, False, True  # default for unknown types

        # windows page protection constants (subset)
        PAGE_NOACCESS = 0x01
        PAGE_READONLY = 0x02
        PAGE_READWRITE = 0x04
        PAGE_WRITECOPY = 0x08  # effectively read-write for mapping purposes
        PAGE_EXECUTE = 0x10
        PAGE_EXECUTE_READ = 0x20
        PAGE_EXECUTE_READWRITE = 0x40
        PAGE_EXECUTE_WRITECOPY = 0x80  # effectively execute-read-write

        # check flags from most privileged to least
        if current_flags_int & PAGE_EXECUTE_READWRITE:
            r, w, x = True, True, True
        elif current_flags_int & PAGE_EXECUTE_WRITECOPY:  # treat as rwx
            r, w, x = True, True, True
        elif current_flags_int & PAGE_EXECUTE_READ:
            r, x = True, True
        elif current_flags_int & PAGE_EXECUTE:
            x = True  # only execute
        elif current_flags_int & PAGE_READWRITE:
            r, w = True, True
        elif current_flags_int & PAGE_WRITECOPY:  # treat as rw
            r, w = True, True
        elif current_flags_int & PAGE_READONLY:
            r = True
        elif current_flags_int & PAGE_NOACCESS:
            # r,w,x remain False
            pass
        # if no flags match (e.g., 0x0), it implies no access or uncommitted memory
        # if current_flags_int is 0 and not PAGE_NOACCESS, it's likely uncommitted, treat as no access.

        return r, w, x

    # - required binaryview method implementations
    #   methods like perform_read, perform_get_length, perform_get_start are
    #   intentionally omitted if add_auto_segment is used correctly, as binary ninja
    #   will use its default implementations based on the defined segments.

    def perform_get_address_size(self) -> int:
        """returns the address size (in bytes) of the architecture."""
        return self._address_size

    def perform_get_default_endianness(self) -> Endianness:
        """returns the default endianness of the architecture."""
        return self._endianness

    def perform_is_executable(self) -> bool:
        """indicates whether the binary view contains executable code."""
        # minidumps typically represent executable processes
        return True

    def perform_is_relocatable(self) -> bool:
        """indicates whether the binary view is relocatable."""
        # memory addresses in a minidump are absolute at the time of dump
        return False

    def perform_get_entry_point(self) -> int:
        """returns the primary entry point address for the binary view."""
        return self._entry_point_to_set


# register the binaryview type with binary ninja
MinidumpView.register()
