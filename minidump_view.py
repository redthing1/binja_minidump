# minidump_view.py
# a binaryview plugin for loading windows minidump files in binary ninja.
# this version uses the 'python-minidump' library (vendored).

import io
import traceback  # for detailed error logging
import datetime  # for timestamp conversion

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

# --- python-minidump library integration ---
# assumes the library is vendored in a 'lib' subdirectory relative to this file
try:
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
    )  # Assuming this enum exists

    # import common structs potentially needed
    from .lib.minidump.common_structs import (
        MinidumpMemorySegment,
    )  # Needed for segment iteration

except ImportError as e:
    # log an error if the library isn't found where expected.
    print(f"[MinidumpLoader] Error: Failed to import vendored 'minidump' library: {e}")
    print(
        "[MinidumpLoader] Ensure the library is placed correctly in the './lib/minidump' subdirectory of the plugin."
    )
    raise  # prevent plugin from loading incorrectly


class MinidumpView(BinaryView):
    """
    binaryview for windows minidump files, using the python-minidump library.
    parses the dump, maps memory, identifies modules/threads, etc.
    """

    name = "Minidump"  # distinguish from other potential loaders
    long_name = "Windows Minidump"

    # tag type for marking the crash site
    CRASH_TAG_TYPE_NAME = "Crash Site"
    CRASH_TAG_ICON = "💥"

    # --- Registration and Validation ---
    @classmethod
    def is_valid_for_data(cls, data: BinaryView) -> bool:
        """checks for the 'MDMP' signature."""
        if data.length < 4:
            return False
        magic = data.read(0, 4)
        is_mdmp = magic == b"MDMP"
        if is_mdmp:
            Logger(0, "Minidump").log_info("Valid MDMP signature found.")
        return is_mdmp

    def __init__(self, data: BinaryView):
        """initializes the view instance."""
        super().__init__(file_metadata=data.file, parent_view=data)
        self.raw_data: BinaryView = data  # the raw file view provided by bn
        self.log: Logger = self.create_logger("Minidump")  # tagged logger

        # this will hold the parsed minidump object from the library
        self.mdmp: MinidumpFile | None = None

        # internal state populated during init
        self._address_size: int = 8  # default, updated from systeminfo
        self._endianness: Endianness = Endianness.LittleEndian
        self._platform: Platform | None = None
        self._arch: Architecture | None = None
        self._crash_tag_type: TagType | None = None
        self._min_virtual_address: int = 0xFFFFFFFFFFFFFFFF
        self._max_virtual_address: int = 0
        self._entry_point_to_set: int = 0  # track intended entry point

        # cache memory protections (va -> AllocationProtect enum/int)
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
            return False  # error logged within helper

        # step 2: create custom tag types
        self._crash_tag_type = self._get_or_create_tag_type(
            self.CRASH_TAG_TYPE_NAME, self.CRASH_TAG_ICON
        )

        # step 3: process the parsed streams
        self._process_system_info()
        self._process_memory_info_list()  # caches protections
        self._process_memory_segments()
        self._process_module_list()
        self._process_unloaded_module_list()
        self._process_thread_list()
        self._process_exception_stream()  # may update entry point
        self._process_handle_data_stream()
        self._process_misc_info()

        # step 4: finalize bn view setup (sets entry point)
        self._finalize_view_setup()

        self.log.log_info("Minidump initialization complete.")
        return True

    # --- Helper methods for parsing and processing ---

    def _parse_minidump_with_library(self) -> bool:
        """helper: reads raw file data and parses it using the python-minidump library."""
        self.log.log_debug("Reading raw file data for python-minidump parsing...")
        try:
            file_bytes = self.raw_data.read(0, self.raw_data.length)
            file_like_object = io.BytesIO(file_bytes)
            # use the library's parse_buff method
            self.mdmp = MinidumpFile.parse_buff(file_like_object)
            self.log.log_info("python-minidump parsing successful.")
            if self.mdmp.header:
                self.log.log_debug(
                    f"  Parsed Header: Streams={self.mdmp.header.NumberOfStreams}, Flags=0x{self.mdmp.header.Flags:016x}"
                )
            return True
        except Exception as e:
            self.log.log_error(f"python-minidump parsing failed: {e}")
            self.log.log_error(traceback.format_exc())
            self.mdmp = None
            return False

    def _process_system_info(self) -> None:
        """helper: processes systeminfo stream to set platform and architecture."""
        if not self.mdmp or not self.mdmp.sysinfo:
            self.log.log_warn(
                "SystemInfo stream not found or parsed by library. Platform/arch defaults used."
            )
            return
        self.log.log_debug("Processing SystemInfo stream...")
        sysinfo = self.mdmp.sysinfo
        arch_str, os_str = self._map_system_info_to_platform(sysinfo)
        platform_set_successfully = False
        if arch_str and os_str:
            platform_name = f"{os_str}-{arch_str}"
            try:
                platform_obj = Platform[platform_name]
                self._platform = platform_obj
                self._arch = self._platform.arch
                self._address_size = (
                    self._arch.address_size
                    if self._arch
                    else (8 if "64" in arch_str or arch_str == "aarch64" else 4)
                )
                self.platform = self._platform  # assign to the binaryview property
                platform_set_successfully = True
            except KeyError:
                self.log.log_error(
                    f"Binary Ninja does not have registered platform '{platform_name}'. Analysis impaired."
                )
                self._platform = None
            except Exception as e:
                self.log.log_error(f"Error setting platform '{platform_name}': {e}")
                self._platform = None
        else:
            self.log.log_warn(
                "Could not determine valid platform string from SystemInfo."
            )

        # log details only if platform was successfully set
        if platform_set_successfully and self._platform:
            self.log.log_info(
                f"Platform set to '{self._platform.name}'. Address Size: {self._address_size} bytes."
            )
            try:
                self.log.log_info(
                    f"  OS Version: {sysinfo.MajorVersion}.{sysinfo.MinorVersion} Build {sysinfo.BuildNumber}"
                )
                if sysinfo.CSDVersion:
                    self.log.log_info(f"  Service Pack: {sysinfo.CSDVersion}")
            except AttributeError as e:
                self.log.log_warn(
                    f"Could not log all SystemInfo details (library structure mismatch?): {e}"
                )

    def _process_memory_info_list(self) -> None:
        """helper: processes memoryinfolist stream to cache memory region protections."""
        if (
            not self.mdmp
            or not self.mdmp.memory_info
            or not self.mdmp.memory_info.infos
        ):
            self.log.log_warn(
                "MemoryInfoList stream not found/parsed or empty. Segment permissions may be inaccurate."
            )
            return
        self.log.log_debug(
            f"Processing {len(self.mdmp.memory_info.infos)} entries from MemoryInfoList stream..."
        )
        for mem_info in self.mdmp.memory_info.infos:
            try:
                # cache protection flags (enum or int) by base address
                self._memory_protections[mem_info.BaseAddress] = (
                    mem_info.Protect
                )  # Protect is likely the AllocationProtect enum/int
                self.log.log_debug(
                    f"  MemInfo: VA=0x{mem_info.BaseAddress:x}, Size=0x{mem_info.RegionSize:x}, State={mem_info.State!r}, Protect={mem_info.Protect!r}, Type={mem_info.Type!r}"
                )
            except AttributeError as e:
                self.log.log_error(
                    f"Error accessing attributes in MINIDUMP_MEMORY_INFO (library structure mismatch?): {e}"
                )
        self.log.log_info(
            f"Cached protection info for {len(self._memory_protections)} memory regions."
        )

    def _process_memory_segments(self) -> None:
        """helper: processes memory64liststream or memoryliststream to map memory segments."""
        processed_segments = False
        processed_64bit = False  # track if we successfully processed any 64bit segments

        # prefer 64-bit list if available
        if (
            self.mdmp
            and self.mdmp.memory_segments_64
            and self.mdmp.memory_segments_64.memory_segments
        ):
            self.log.log_debug("Processing Memory64ListStream for memory segments...")
            try:
                # the library pre-processes this into MinidumpMemorySegment objects
                for i, segment in enumerate(
                    self.mdmp.memory_segments_64.memory_segments
                ):
                    # check expected attributes from MinidumpMemorySegment (common_structs.py)
                    if (
                        not hasattr(segment, "start_virtual_address")
                        or segment.start_virtual_address is None
                    ):
                        self.log.log_error(
                            f"Skipping segment object {i} in Memory64ListStream: Missing 'start_virtual_address'. Obj: {segment!r}"
                        )
                        continue
                    if not hasattr(segment, "size") or segment.size is None:
                        self.log.log_error(
                            f"Skipping segment object {i} in Memory64ListStream: Missing 'size'. Obj: {segment!r}"
                        )
                        continue
                    if (
                        not hasattr(segment, "start_file_address")
                        or segment.start_file_address is None
                    ):
                        self.log.log_error(
                            f"Skipping segment object {i} in Memory64ListStream: Missing 'start_file_address'. Obj: {segment!r}"
                        )
                        continue

                    va = segment.start_virtual_address
                    size = segment.size
                    file_offset_in_dump = (
                        segment.start_file_address
                    )  # library uses start_file_address

                    if size == 0:
                        self.log.log_debug(
                            f"  Skipping zero-size segment {i} at VA 0x{va:x} (Memory64List)."
                        )
                        continue

                    self._update_virtual_address_extents(va, size)
                    protection_enum_or_int = self._memory_protections.get(va)
                    r, w, x = self._translate_memory_protection(protection_enum_or_int)
                    # Get the integer representation of the combined flags
                    seg_flags_int = self._build_segment_flags_int(r, w, x)

                    if seg_flags_int != 0:  # Check if there are any permissions
                        self.log.log_info(
                            f"  Adding segment {i} (Memory64List): VA=0x{va:0{self._address_size*2}x}, Size=0x{size:x}, FileOffset=0x{file_offset_in_dump:x}, FlagsInt=0x{seg_flags_int:x}"
                        )
                        # Pass the integer flags directly to add_auto_segment
                        self.add_auto_segment(
                            va, size, file_offset_in_dump, size, seg_flags_int
                        )
                        self._add_segment_comment(
                            va, protection_enum_or_int, r, w, x, "Memory64ListStream"
                        )
                        processed_segments = True
                    else:
                        # Handle PAGE_NOACCESS case (or other zero-permission cases)
                        self.log.log_warn(
                            f"  Skipping segment {i} (Memory64List) at VA=0x{va:0{self._address_size*2}x} due to zero permissions (Protection: {protection_enum_or_int!r})."
                        )

                processed_64bit = processed_segments  # mark success if loop completed without error breaking it

            except Exception as e:
                self.log.log_error(
                    f"Unexpected error during Memory64ListStream processing: {e}"
                )
                self.log.log_error(traceback.format_exc())
                processed_64bit = False  # ensure fallback if unexpected error occurs

        # fallback to 32-bit list only if 64-bit list was NOT present OR failed processing
        if (
            not processed_64bit
            and self.mdmp
            and self.mdmp.memory_segments
            and self.mdmp.memory_segments.memory_segments
        ):
            self.log.log_debug("Processing MemoryListStream for memory segments...")
            try:
                for i, segment in enumerate(self.mdmp.memory_segments.memory_segments):
                    # check expected attributes from MinidumpMemorySegment
                    if (
                        not hasattr(segment, "start_virtual_address")
                        or segment.start_virtual_address is None
                    ):
                        self.log.log_error(
                            f"Skipping segment object {i} in MemoryListStream: Missing 'start_virtual_address'. Obj: {segment!r}"
                        )
                        continue
                    if not hasattr(segment, "size") or segment.size is None:
                        self.log.log_error(
                            f"Skipping segment object {i} in MemoryListStream: Missing 'size'. Obj: {segment!r}"
                        )
                        continue
                    if (
                        not hasattr(segment, "start_file_address")
                        or segment.start_file_address is None
                    ):
                        self.log.log_error(
                            f"Skipping segment object {i} in MemoryListStream: Missing 'start_file_address'. Obj: {segment!r}"
                        )
                        continue

                    va = segment.start_virtual_address
                    size = segment.size
                    file_offset_in_dump = (
                        segment.start_file_address
                    )  # library provides this correctly
                    if size == 0:
                        self.log.log_debug(
                            f"  Skipping zero-size segment {i} at VA 0x{va:x} (MemoryList)."
                        )
                        continue
                    self._update_virtual_address_extents(va, size)
                    protection_enum_or_int = self._memory_protections.get(va)
                    r, w, x = self._translate_memory_protection(protection_enum_or_int)
                    seg_flags_int = self._build_segment_flags_int(r, w, x)

                    if seg_flags_int != 0:
                        self.log.log_info(
                            f"  Adding segment {i} (MemoryList): VA=0x{va:0{self._address_size*2}x}, Size=0x{size:x}, FileOffset=0x{file_offset_in_dump:x}, FlagsInt=0x{seg_flags_int:x}"
                        )
                        self.add_auto_segment(
                            va, size, file_offset_in_dump, size, seg_flags_int
                        )
                        self._add_segment_comment(
                            va, protection_enum_or_int, r, w, x, "MemoryListStream"
                        )
                        processed_segments = True
                    else:
                        self.log.log_warn(
                            f"  Skipping segment {i} (MemoryList) at VA=0x{va:0{self._address_size*2}x} due to zero permissions (Protection: {protection_enum_or_int!r})."
                        )

            except Exception as e:
                self.log.log_error(
                    f"Unexpected error during MemoryListStream processing: {e}"
                )
                self.log.log_error(traceback.format_exc())

        if not processed_segments:
            self.log.log_warn(
                "No memory segments could be successfully processed. Memory map will be empty."
            )

    def _update_virtual_address_extents(self, va: int, size: int):
        """helper: updates the overall min/max virtual addresses based on a new segment."""
        self._min_virtual_address = min(self._min_virtual_address, va)
        self._max_virtual_address = max(self._max_virtual_address, va + size)

    def _build_segment_flags_int(self, r: bool, w: bool, x: bool) -> int:
        """
        helper: constructs an integer representing combined segment flags.
        returns 0 if no permissions are set.
        """
        flags_val = 0
        if r:
            flags_val |= SegmentFlag.SegmentReadable.value
        if w:
            flags_val |= SegmentFlag.SegmentWritable.value
        if x:
            flags_val |= SegmentFlag.SegmentExecutable.value
        # Optionally add ContainsData/ContainsCode based on heuristics
        if x:
            flags_val |= SegmentFlag.SegmentContainsCode.value
        elif r or w:  # If readable or writable but not executable, assume data
            flags_val |= SegmentFlag.SegmentContainsData.value

        return flags_val

    def _add_segment_comment(
        self,
        va: int,
        protection_enum_or_int,
        r: bool,
        w: bool,
        x: bool,
        stream_name: str,
    ):
        """helper: adds a descriptive comment to a newly added segment."""
        protection_str = (
            str(protection_enum_or_int)
            if protection_enum_or_int is not None
            else "Unknown (MemoryInfoList missing/incomplete)"
        )
        if hasattr(protection_enum_or_int, "name"):
            protection_str = protection_enum_or_int.name
        self.set_comment_at(
            va,
            f"Minidump Memory Segment (from {stream_name})\nOriginal Protection: {protection_str}\nMapped Permissions: R={'Y' if r else 'N'}, W={'Y' if w else 'N'}, X={'Y' if x else 'N'}",
        )

    def _process_module_list(self) -> None:
        """helper: processes modulelist stream to define sections and symbols."""
        if not self.mdmp or not self.mdmp.modules or not self.mdmp.modules.modules:
            self.log.log_warn(
                "ModuleList stream not found/parsed or empty. No modules defined."
            )
            return
        self.log.log_info(
            f"Processing {len(self.mdmp.modules.modules)} modules from ModuleListStream."
        )
        for i, mod in enumerate(self.mdmp.modules.modules):
            try:
                # check expected attributes from MinidumpModule
                if (
                    not hasattr(mod, "name")
                    or not hasattr(mod, "baseaddress")
                    or not hasattr(mod, "size")
                ):
                    self.log.log_error(
                        f"Skipping module entry {i} due to missing attributes (name/baseaddress/size). Obj: {mod!r}"
                    )
                    continue

                name = mod.name if mod.name else f"UnknownModule_0x{mod.baseaddress:x}"
                base_va = mod.baseaddress
                size = mod.size
                timestamp_val = mod.timestamp if hasattr(mod, "timestamp") else "N/A"
                checksum_val = mod.checksum if hasattr(mod, "checksum") else "N/A"

                # check for None values that are critical
                if base_va is None or size is None:
                    self.log.log_error(
                        f"Skipping module entry {i} ('{name}') due to missing base address or size: Base={base_va}, Size={size}"
                    )
                    continue
                if size <= 0:
                    self.log.log_warn(
                        f"  Skipping module {i} ('{name}') due to zero or negative size: {size}"
                    )
                    continue

                self.log.log_info(
                    f"  Adding module {i}: {name}, BaseVA=0x{base_va:0{self._address_size*2}x}, Size=0x{size:x}"
                )
                self.add_auto_section(
                    name, base_va, size, SectionSemantics.ReadOnlyCodeSectionSemantics
                )
                # corrected SymbolType enum member name based on binaryninja_enums.txt
                symbol_name = str(name)  # Ensure string
                # Use the correct enum member: LibraryFunctionSymbol
                self.define_auto_symbol(
                    Symbol(SymbolType.LibraryFunctionSymbol, base_va, symbol_name)
                )

                try:
                    if isinstance(timestamp_val, int):
                        timestamp_dt = datetime.datetime.fromtimestamp(
                            timestamp_val, tz=datetime.timezone.utc
                        )
                        timestamp_str = timestamp_dt.isoformat()
                    else:
                        timestamp_str = str(timestamp_val)  # Handle N/A or other types
                except Exception:
                    timestamp_str = f"Invalid raw 0x{timestamp_val:x}"

                checksum_str = (
                    f"0x{checksum_val:x}"
                    if isinstance(checksum_val, int)
                    else str(checksum_val)
                )
                self.set_comment_at(
                    base_va,
                    f"Module: {symbol_name}\nBase: 0x{base_va:x}\nSize: 0x{size:x}\nTimestamp: {timestamp_str} (Raw: {timestamp_val!r})\nChecksum: {checksum_str}",
                )

            except Exception as e:  # Catch broader errors
                self.log.log_error(f"Error processing module entry {i}: {e}")
                self.log.log_error(traceback.format_exc())
                continue

    def _process_thread_list(self) -> None:
        """helper: processes threadlist stream for thread info, stacks, and contexts."""
        if not self.mdmp or not self.mdmp.threads or not self.mdmp.threads.threads:
            self.log.log_warn(
                "ThreadList stream not found/parsed or empty. No threads defined."
            )
            return
        self.log.log_info(
            f"Processing {len(self.mdmp.threads.threads)} threads from ThreadListStream."
        )
        for i, thread_entry in enumerate(self.mdmp.threads.threads):
            try:
                # check attributes from MINIDUMP_THREAD and nested structures
                # Corrected check: MemoryLocation is nested inside Stack
                if (
                    not hasattr(thread_entry, "ThreadId")
                    or not hasattr(thread_entry, "Stack")
                    or not hasattr(thread_entry.Stack, "StartOfMemoryRange")
                    or not hasattr(thread_entry.Stack, "MemoryLocation")
                    or not hasattr(thread_entry.Stack.MemoryLocation, "DataSize")
                    or not hasattr(thread_entry, "Teb")
                    or not hasattr(thread_entry, "ThreadContext")
                ):
                    self.log.log_error(
                        f"Skipping thread entry {i} due to missing attributes. Obj: {thread_entry!r}"
                    )
                    continue

                tid = thread_entry.ThreadId
                stack_va = thread_entry.Stack.StartOfMemoryRange
                # corrected access path for stack size based on common_structs.py
                stack_size = thread_entry.Stack.MemoryLocation.DataSize
                teb = thread_entry.Teb
                self.log.log_info(
                    f"  Thread ID: {tid}, Stack Start: 0x{stack_va:x}, Stack Size: 0x{stack_size:x}, TEB: 0x{teb:x}"
                )
                self.set_comment_at(
                    stack_va,
                    f"Thread {tid} Stack (Size: 0x{stack_size:x}, TEB: 0x{teb:x})",
                )
                self.define_auto_symbol(
                    Symbol(SymbolType.DataSymbol, stack_va, f"Thread_{tid}_StackBase")
                )
                context_loc = (
                    thread_entry.ThreadContext
                )  # This is MINIDUMP_LOCATION_DESCRIPTOR
                self.log.log_debug(
                    f"    Thread {tid} context location: RVA=0x{context_loc.Rva:x}, Size=0x{context_loc.DataSize:x}"
                )
                self.log.log_warn(
                    f"    Thread {tid}: Detailed context parsing (registers) requires manual parsing of data at RVA 0x{context_loc.Rva:x} based on architecture."
                )
            except AttributeError as e:
                self.log.log_error(
                    f"Error processing thread entry {i} (library structure mismatch?): {e}"
                )
                continue

    def _process_exception_stream(self) -> None:
        """helper: processes the exception stream, if present."""
        if (
            not self.mdmp
            or not self.mdmp.exception
            or not self.mdmp.exception.exception_records
        ):
            self.log.log_debug(
                "No ExceptionStream found or no records (dump may not be from a crash)."
            )
            return
        self.log.log_info(
            f"Processing {len(self.mdmp.exception.exception_records)} exception record(s)..."
        )
        try:
            record_stream = self.mdmp.exception.exception_records[0]
            record = record_stream.ExceptionRecord
            thread_id = record_stream.ThreadId
            exc_addr = record.ExceptionAddress
            exc_code_val = record.ExceptionCode_raw
            exc_flags_val = record.ExceptionFlags
            exc_code_str = self._map_exception_code_to_string(exc_code_val)
            self.log.log_warn(f"  EXCEPTION Occurred in Thread ID: {thread_id}")
            self.log.log_warn(f"  Exception Code: 0x{exc_code_val:X} ({exc_code_str})")
            self.log.log_warn(f"  Exception Flags: 0x{exc_flags_val:X}")
            self.log.log_warn(
                f"  Exception Address (Faulting IP): 0x{exc_addr:0{self._address_size*2}x}"
            )
            comment = f"== MINIDUMP CRASH SITE ==\nThread ID: {thread_id}\nException Code: 0x{exc_code_val:X} ({exc_code_str})\nFaulting Address: 0x{exc_addr:0{self._address_size*2}x}"
            if hasattr(record, "ExceptionInformation") and record.NumberParameters > 0:
                params_to_show = record.ExceptionInformation[: record.NumberParameters]
                params_str = ", ".join([f"0x{p:x}" for p in params_to_show])
                comment += f"\nException Parameters: [{params_str}]"
                self.log.log_warn(f"  Exception Parameters: [{params_str}]")
            self.set_comment_at(exc_addr, comment)
            if self._crash_tag_type:
                self.add_tag(exc_addr, self._crash_tag_type, f"Crash: {exc_code_str}")
            self.log.log_info(
                f"Setting intended entry point to exception address 0x{exc_addr:x}"
            )
            self._entry_point_to_set = exc_addr  # Store the intended entry point
        except AttributeError as e:
            self.log.log_error(
                f"Error accessing attributes in ExceptionStream (library structure mismatch?): {e}"
            )
        except Exception as e:
            self.log.log_error(f"Unexpected error processing ExceptionStream: {e}")

    def _map_exception_code_to_string(self, code: int) -> str:
        """Maps common Windows exception codes to human-readable strings."""
        common_codes = {
            0xC0000005: "Access Violation",
            0x80000003: "Breakpoint",
            0xC00000FD: "Stack Overflow",
            0xC000001D: "Illegal Instruction",
        }  # Add more as needed
        return common_codes.get(code, f"Unknown (0x{code:X})")

    def _process_unloaded_module_list(self) -> None:
        """helper: logs information about unloaded modules."""
        if (
            not self.mdmp
            or not self.mdmp.unloaded_modules
            or not self.mdmp.unloaded_modules.modules
        ):
            self.log.log_debug("No UnloadedModuleList stream found/parsed or empty.")
            return
        self.log.log_info(
            f"Processing {len(self.mdmp.unloaded_modules.modules)} unloaded modules."
        )
        for mod in self.mdmp.unloaded_modules.modules:
            try:
                name = (
                    mod.name if mod.name else f"UnknownUnloaded_0x{mod.baseaddress:x}"
                )
                self.log.log_info(
                    f"  Unloaded Module: {name}, Base: 0x{mod.baseaddress:x}, Size: 0x{mod.size:x}, Timestamp: 0x{mod.timestamp:x}"
                )
            except AttributeError as e:
                self.log.log_warn(
                    f"Could not fully parse an unloaded module entry (library structure mismatch?): {e}"
                )

    def _process_handle_data_stream(self) -> None:
        """helper: logs basic information about open handles."""
        if not self.mdmp or not self.mdmp.handles or not self.mdmp.handles.handles:
            self.log.log_debug("No HandleData stream found/parsed or empty.")
            return
        self.log.log_info(
            f"Processing {len(self.mdmp.handles.handles)} handles from HandleDataStream."
        )
        for i, handle in enumerate(self.mdmp.handles.handles):
            try:
                self.log.log_debug(
                    f"  Handle {i}: Value=0x{handle.Handle:x}, Type='{handle.TypeName}', Name='{handle.ObjectName}', Attr=0x{handle.Attributes:x}"
                )
            except AttributeError as e:
                self.log.log_warn(
                    f"Could not fully parse handle entry {i} (library structure mismatch?): {e}"
                )

    def _process_misc_info(self) -> None:
        """helper: logs miscellaneous process information."""
        if not self.mdmp or not self.mdmp.misc_info:
            self.log.log_debug("No MiscInfo stream found/parsed.")
            return
        self.log.log_info("Processing MiscInfoStream...")
        misc_info = self.mdmp.misc_info
        try:
            pid_val = misc_info.ProcessId
            create_time_raw = misc_info.ProcessCreateTime
            try:
                create_time_dt = datetime.datetime.fromtimestamp(
                    create_time_raw, tz=datetime.timezone.utc
                )
                create_time_str = create_time_dt.isoformat()
            except Exception as ts_ex:
                create_time_str = f"Invalid raw 0x{create_time_raw:x} ({ts_ex})"
            self.log.log_info(f"  Process ID (PID): {pid_val}")
            self.log.log_info(
                f"  Process Create Time: {create_time_str} (Raw: 0x{create_time_raw:x})"
            )
            if misc_info.ProcessUserTime is not None:
                self.log.log_info(f"  Process User Time: {misc_info.ProcessUserTime}")
            if misc_info.ProcessKernelTime is not None:
                self.log.log_info(
                    f"  Process Kernel Time: {misc_info.ProcessKernelTime}"
                )
            if misc_info.ProcessorMaxMhz is not None:
                self.log.log_info(f"  CPU Max MHz: {misc_info.ProcessorMaxMhz}")
            if misc_info.ProcessorCurrentMhz is not None:
                self.log.log_info(f"  CPU Current MHz: {misc_info.ProcessorCurrentMhz}")
        except AttributeError as e:
            self.log.log_warn(
                f"Could not fully parse MiscInfoStream (library structure mismatch?): {e}"
            )

    def _finalize_view_setup(self) -> None:
        """helper: performs final setup steps, like setting the entry point."""
        # if exception stream didn't set an entry point, use the default (min VA or 0)
        if (
            self._entry_point_to_set == 0
            and self._min_virtual_address != 0xFFFFFFFFFFFFFFFF
        ):
            self._entry_point_to_set = self._min_virtual_address

        self.log.log_info(
            f"Finalizing setup. Setting entry point to 0x{self._entry_point_to_set:x}"
        )
        # use the BinaryView API to add the entry point
        self.add_entry_point(self._entry_point_to_set)
        self.log.log_info("View setup finalized. Ready for analysis.")

    def _get_or_create_tag_type(self, name: str, icon: str) -> TagType | None:
        """helper: gets an existing tag type or creates it if it doesn't exist, caching the result."""
        try:
            tag_type = self.get_tag_type(name)
            if tag_type:
                return tag_type
        except KeyError:
            pass
        except Exception as e:
            self.log.log_warn(f"Error checking TagType '{name}': {e}")
        try:
            self.log.log_info(f"Creating new TagType '{name}' with icon '{icon}'.")
            return self.create_tag_type(name, icon)
        except Exception as e:
            self.log.log_error(
                f"Failed to create TagType '{name}': {e}. Trying get again."
            )
            try:
                return self.get_tag_type(name)
            except Exception:
                self.log.log_error(f"Still failed to get TagType '{name}'.")
                return None

    def _map_system_info_to_platform(
        self, sys_info_data
    ) -> tuple[str | None, str | None]:
        """helper: maps minidump system info to bn platform/arch strings."""
        arch_str: str | None = None
        os_str: str | None = "windows"
        try:
            cpu_arch_enum = (
                sys_info_data.ProcessorArchitecture
            )  # From PROCESSOR_ARCHITECTURE enum
            if cpu_arch_enum == PROCESSOR_ARCHITECTURE.AMD64:
                arch_str = "x86_64"
            elif cpu_arch_enum == PROCESSOR_ARCHITECTURE.INTEL:
                arch_str = "x86"
            elif cpu_arch_enum == PROCESSOR_ARCHITECTURE.ARM:
                arch_str = "armv7"
            elif cpu_arch_enum == PROCESSOR_ARCHITECTURE.IA64:
                arch_str = "ia64"
            elif cpu_arch_enum == PROCESSOR_ARCHITECTURE.AARCH64:
                arch_str = "aarch64"
            elif cpu_arch_enum == PROCESSOR_ARCHITECTURE.UNKNOWN:
                self.log.log_warn("CPU arch unknown.")
                return None, os_str
            else:
                self.log.log_warn(
                    f"Unrecognized CPU arch enum value: {cpu_arch_enum!r}"
                )
                return None, os_str
            return arch_str, os_str
        except AttributeError as e:
            self.log.log_error(
                f"Error accessing sysinfo attrs (library structure mismatch?): {e}"
            )
            return None, None
        except Exception as e:
            self.log.log_error(f"Unexpected error mapping sysinfo: {e}")
            return None, None

    def _translate_memory_protection(
        self, minidump_protect_flags_val
    ) -> tuple[bool, bool, bool]:
        """helper: translates minidump memory protection flags (int) to r,w,x booleans."""
        if minidump_protect_flags_val is None:
            return True, False, True  # Default R-X
        r, w, x = False, False, False
        current_flags = minidump_protect_flags_val
        if isinstance(current_flags, AllocationProtect):  # Check if it's the enum
            current_flags = current_flags.value  # Get the integer value

        if isinstance(current_flags, int):
            PAGE_NOACCESS = 0x01
            PAGE_READONLY = 0x02
            PAGE_READWRITE = 0x04
            PAGE_WRITECOPY = 0x08
            PAGE_EXECUTE = 0x10
            PAGE_EXECUTE_READ = 0x20
            PAGE_EXECUTE_READWRITE = 0x40
            PAGE_EXECUTE_WRITECOPY = 0x80
            if current_flags & PAGE_EXECUTE_READWRITE:
                r, w, x = True, True, True
            elif current_flags & PAGE_EXECUTE_WRITECOPY:
                r, w, x = True, True, True
            elif current_flags & PAGE_EXECUTE_READ:
                r, x = True, True
            elif current_flags & PAGE_EXECUTE:
                x = True
            elif current_flags & PAGE_READWRITE:
                r, w = True, True
            elif current_flags & PAGE_WRITECOPY:
                r, w = True, True
            elif current_flags & PAGE_READONLY:
                r = True
        else:
            self.log.log_warn(
                f"Unknown protection flag type: {minidump_protect_flags_val!r}. Defaulting to R-X."
            )
            return True, False, True
        return r, w, x

    # --- required binaryview method implementations ---

    def perform_get_address_size(self) -> int:
        return self._address_size

    def perform_get_default_endianness(self) -> Endianness:
        return self._endianness

    def perform_is_executable(self) -> bool:
        return True

    def perform_is_relocatable(self) -> bool:
        return False

    def perform_get_entry_point(self) -> int:
        return self._entry_point_to_set

    def perform_get_length(self) -> int:
        if (
            self._max_virtual_address == 0
            and self._min_virtual_address == 0xFFFFFFFFFFFFFFFF
        ):
            self.log.log_warn(
                "perform_get_length: No segments defined or min/max VA not updated. Returning 0."
            )
            return 0
        return self._max_virtual_address - self._min_virtual_address

    def perform_get_start(self) -> int:
        if self._min_virtual_address == 0xFFFFFFFFFFFFFFFF:
            self.log.log_warn(
                "perform_get_start: Min virtual address not set (no segments?). Returning 0."
            )
            return 0
        return self._min_virtual_address

    def perform_read(self, addr: int, length: int) -> bytes | None:
        for seg in self.segments:
            if seg.start <= addr < seg.end:
                offset_in_segment = addr - seg.start
                readable_length_in_segment = seg.end - addr
                actual_length_to_read = min(length, readable_length_in_segment)
                if actual_length_to_read <= 0:
                    return b""
                file_addr = seg.data_offset + offset_in_segment
                if offset_in_segment + actual_length_to_read > seg.data_length:
                    available_from_backing = seg.data_length - offset_in_segment
                    if available_from_backing <= 0:
                        return b""
                    actual_length_to_read = available_from_backing
                if actual_length_to_read <= 0:
                    return b""
                try:
                    return self.raw_data.read(file_addr, actual_length_to_read)
                except Exception as e:
                    self.log.log_error(
                        f"perform_read error at file offset 0x{file_addr:x}: {e}"
                    )
                    return None
        return None


MinidumpView.register()
