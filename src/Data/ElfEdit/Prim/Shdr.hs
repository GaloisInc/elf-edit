{-|
Declares primitive representation of section headers.
-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE PatternSynonyms #-}
module Data.ElfEdit.Prim.Shdr
  ( -- * Section headers
    Shdr(..)
  , shdrFileSize
  , shdrFileRange
    -- ** Special section headers
  , initShdr
    -- ** Encoding
  , shdrEntrySize
  , shdrTableAlign
  , decodeShdr
  , encodeShdr
  , encodeShdrTable
    -- ** ElfSectionIndex
  , ElfSectionIndex(..)
  , pattern SHN_UNDEF
  , pattern SHN_ABS
  , pattern SHN_COMMON
  , pattern SHN_LORESERVE
  , pattern SHN_LOPROC
  , pattern SHN_X86_64_LCOMMON
  , pattern SHN_IA_64_ANSI_COMMON
  , pattern SHN_MIPS_SCOMMON
  , pattern SHN_MIPS_SUNDEFINED
  , pattern SHN_TIC6X_SCOMMON
  , pattern SHN_HIPROC
  , pattern SHN_LOOS
  , pattern SHN_HIOS
  , ppElfSectionIndex
    -- ** Elf section type
  , ElfSectionType(..)
  , pattern SHT_NULL
  , pattern SHT_PROGBITS
  , pattern SHT_SYMTAB
  , pattern SHT_STRTAB
  , pattern SHT_RELA
  , pattern SHT_HASH
  , pattern SHT_DYNAMIC
  , pattern SHT_NOTE
  , pattern SHT_NOBITS
  , pattern SHT_REL
  , pattern SHT_SHLIB
  , pattern SHT_DYNSYM
    -- ** Elf section flags
  , ElfSectionFlags(..)
  , shf_none
  , shf_write
  , shf_alloc
  , shf_execinstr
  , shf_merge
  , shf_strings
  , shf_info_link
  , shf_link_order
  , shf_os_nonconforming
  , shf_group
  , shf_tls
  , shf_compressed
  ) where

import           Data.Binary.Get
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Builder as Bld
import qualified Data.Map.Strict as Map
import qualified Data.Vector as V
import           Data.Word
import           Numeric

import           Data.ElfEdit.Prim.Ehdr
import           Data.ElfEdit.Prim.File
import           Data.ElfEdit.Utils (showFlags, strictRunGetOrFail)

------------------------------------------------------------------------
-- ElfSectionIndex

-- | Identifier to identify sections
newtype ElfSectionIndex = ElfSectionIndex { fromElfSectionIndex :: Word16 }
  deriving (Eq, Ord, Enum, Num, Real, Integral)

-- | Undefined section
pattern SHN_UNDEF :: ElfSectionIndex
pattern SHN_UNDEF = ElfSectionIndex 0

-- | Start of reserved indices.
pattern SHN_LORESERVE :: ElfSectionIndex
pattern SHN_LORESERVE = ElfSectionIndex 0xff00

-- | Associated symbol is absolute.
pattern SHN_ABS :: ElfSectionIndex
pattern SHN_ABS = ElfSectionIndex 0xfff1

-- | This identifies a symbol in a relocatable file that is not yet allocated.
--
-- The linker should allocate space for this symbol at an address that
-- is a aligned to the symbol value.
pattern SHN_COMMON :: ElfSectionIndex
pattern SHN_COMMON = ElfSectionIndex 0xfff2

-- | Start of processor specific.
pattern SHN_LOPROC :: ElfSectionIndex
pattern SHN_LOPROC = SHN_LORESERVE

-- | Like SHN_COMMON but symbol in .lbss
pattern SHN_X86_64_LCOMMON :: ElfSectionIndex
pattern SHN_X86_64_LCOMMON = ElfSectionIndex 0xff02

-- | Only used by HP-UX, because HP linker gives
-- weak symbols precdence over regular common symbols.
pattern SHN_IA_64_ANSI_COMMON :: ElfSectionIndex
pattern SHN_IA_64_ANSI_COMMON = SHN_LORESERVE

-- | Small common symbols
pattern SHN_MIPS_SCOMMON :: ElfSectionIndex
pattern SHN_MIPS_SCOMMON = ElfSectionIndex 0xff03

-- | Small undefined symbols
pattern SHN_MIPS_SUNDEFINED :: ElfSectionIndex
pattern SHN_MIPS_SUNDEFINED = ElfSectionIndex 0xff04

-- | Small data area common symbol.
pattern SHN_TIC6X_SCOMMON :: ElfSectionIndex
pattern SHN_TIC6X_SCOMMON = SHN_LORESERVE

-- | End of processor specific.
pattern SHN_HIPROC :: ElfSectionIndex
pattern SHN_HIPROC = ElfSectionIndex 0xff1f

-- | Start of OS-specific.
pattern SHN_LOOS :: ElfSectionIndex
pattern SHN_LOOS = ElfSectionIndex 0xff20

-- | End of OS-specific.
pattern SHN_HIOS :: ElfSectionIndex
pattern SHN_HIOS = ElfSectionIndex 0xff3f

instance Show ElfSectionIndex where
  show i = ppElfSectionIndex EM_NONE ELFOSABI_SYSV maxBound "SHN_" i

-- | Pretty print an elf section index
ppElfSectionIndex :: ElfMachine
                  -> ElfOSABI
                  -> Word16 -- ^ Number of sections.
                  -> String -- ^ Prefix for names
                  -> ElfSectionIndex
                  -> String
ppElfSectionIndex m abi this_shnum pre tp =
  case tp of
    SHN_UNDEF -> pre ++ "UND"
    SHN_ABS   -> pre ++ "ABS"
    SHN_COMMON -> pre ++ "COM"
    SHN_IA_64_ANSI_COMMON | m == EM_IA_64 && abi == ELFOSABI_HPUX   -> pre ++ "ANSI_COM"
    SHN_X86_64_LCOMMON    | m `elem` [ EM_X86_64, EM_L1OM, EM_K1OM] -> pre ++ "LARGE_COM"
    SHN_MIPS_SCOMMON      | m == EM_MIPS                            -> pre ++ "SCOM"
    SHN_MIPS_SUNDEFINED   | m == EM_MIPS                            -> pre ++ "SUND"
    SHN_TIC6X_SCOMMON     | m == EM_TI_C6000                        -> pre ++ "SCOM"

    ElfSectionIndex w
      | tp >= SHN_LOPROC && tp <= SHN_HIPROC   -> pre ++ "PRC[0x" ++ showHex w "]"
      | tp >= SHN_LOOS   && tp <= SHN_HIOS     -> pre ++ "OS [0x" ++ showHex w "]"
      | tp >= SHN_LORESERVE                  -> pre ++ "RSV[0x" ++ showHex w "]"
      | w >= this_shnum                      -> "bad section index[" ++ show w ++ "]"
      | otherwise                            -> show w

------------------------------------------------------------------------
-- ElfSectionType

-- | The type associated with an Elf file.
newtype ElfSectionType = ElfSectionType { fromElfSectionType :: Word32 }
  deriving (Eq, Ord)

-- | Identifies an empty section header.
pattern SHT_NULL :: ElfSectionType
pattern SHT_NULL     = ElfSectionType  0
-- | Contains information defined by the program
pattern SHT_PROGBITS :: ElfSectionType
pattern SHT_PROGBITS = ElfSectionType  1
-- | Contains a linker symbol table
pattern SHT_SYMTAB :: ElfSectionType
pattern SHT_SYMTAB   = ElfSectionType  2
-- | Contains a string table
pattern SHT_STRTAB :: ElfSectionType
pattern SHT_STRTAB   = ElfSectionType  3
-- | Contains "Rela" type relocation entries
pattern SHT_RELA :: ElfSectionType
pattern SHT_RELA     = ElfSectionType  4
-- | Contains a symbol hash table
pattern SHT_HASH :: ElfSectionType
pattern SHT_HASH     = ElfSectionType  5
-- | Contains dynamic linking tables
pattern SHT_DYNAMIC :: ElfSectionType
pattern SHT_DYNAMIC  = ElfSectionType  6
-- | Contains note information
pattern SHT_NOTE :: ElfSectionType
pattern SHT_NOTE     = ElfSectionType  7
-- | Contains uninitialized space; does not occupy any space in the file
pattern SHT_NOBITS :: ElfSectionType
pattern SHT_NOBITS   = ElfSectionType  8
-- | Contains "Rel" type relocation entries
pattern SHT_REL :: ElfSectionType
pattern SHT_REL = ElfSectionType  9
-- | Reserved
pattern SHT_SHLIB :: ElfSectionType
pattern SHT_SHLIB = ElfSectionType 10
-- | Contains a dynamic loader symbol table
pattern SHT_DYNSYM :: ElfSectionType
pattern SHT_DYNSYM   = ElfSectionType 11

-- | Pointers to initialization  functions.
pattern SHT_INIT_ARRAY :: ElfSectionType
pattern SHT_INIT_ARRAY = ElfSectionType 14

-- | Pointers to termination functions.
pattern SHT_FINI_ARRAY :: ElfSectionType
pattern SHT_FINI_ARRAY = ElfSectionType 15

-- | Pointers to  pre-init functions.
pattern SHT_PREINIT_ARRAY :: ElfSectionType
pattern SHT_PREINIT_ARRAY = ElfSectionType 16

-- | Section group
pattern SHT_GROUP :: ElfSectionType
pattern SHT_GROUP = ElfSectionType 17

-- | Indices for SHN_XINDEX entries.
pattern SHT_SYMTAB_SHNDX :: ElfSectionType
pattern SHT_SYMTAB_SHNDX = ElfSectionType 18

-- |  OS-specific section header types.
pattern SHT_LOOS :: ElfSectionType
pattern SHT_LOOS = ElfSectionType 0x60000000

-- | Android packed relocation section.
pattern SHT_ANDROID_REL :: ElfSectionType
pattern SHT_ANDROID_REL = ElfSectionType 0x60000001

-- | Android packed relocation section.
pattern SHT_ANDROID_RELA :: ElfSectionType
pattern SHT_ANDROID_RELA = ElfSectionType 0x60000002

-- | Object attributes.
pattern SHT_GNU_ATTRIBUTES :: ElfSectionType
pattern SHT_GNU_ATTRIBUTES = ElfSectionType 0x6ffffff5
-- | GNU-style hash table.
pattern SHT_GNU_HASH :: ElfSectionType
pattern SHT_GNU_HASH = ElfSectionType 0x6ffffff6
-- | GNU version definitions.
pattern SHT_GNU_verdef :: ElfSectionType
pattern SHT_GNU_verdef = ElfSectionType 0x6ffffffd
-- | GNU version references.
pattern SHT_GNU_verneed :: ElfSectionType
pattern SHT_GNU_verneed = ElfSectionType 0x6ffffffe
-- | GNU symbol versions table.
pattern SHT_GNU_versym :: ElfSectionType
pattern SHT_GNU_versym = ElfSectionType 0x6fffffff
-- | Highest operating system-specific type.
pattern SHT_HIOS :: ElfSectionType
pattern SHT_HIOS = ElfSectionType 0x6fffffff

-- | Lowest processor arch-specific type.
pattern SHT_LOPROC :: ElfSectionType
pattern SHT_LOPROC = ElfSectionType 0x70000000
-- |  Exception Index table
pattern SHT_ARM_EXIDX :: ElfSectionType
pattern SHT_ARM_EXIDX = ElfSectionType 0x70000001
-- | BPABI DLL dynamic linking pre-emption map
pattern SHT_ARM_PREEMPTMAP :: ElfSectionType
pattern SHT_ARM_PREEMPTMAP = ElfSectionType 0x70000002

pattern SHT_ARM_ATTRIBUTES     :: ElfSectionType
pattern SHT_ARM_ATTRIBUTES     = ElfSectionType 0x70000003
pattern SHT_ARM_DEBUGOVERLAY   :: ElfSectionType
pattern SHT_ARM_DEBUGOVERLAY   = ElfSectionType 0x70000004
pattern SHT_ARM_OVERLAYSECTION :: ElfSectionType
pattern SHT_ARM_OVERLAYSECTION = ElfSectionType 0x70000005

sectionTagMap :: Map.Map ElfSectionType String
sectionTagMap = Map.fromList
  [ (,) SHT_NULL      "SHT_NULL"
  , (,) SHT_PROGBITS  "SHT_PROGBITS"
  , (,) SHT_SYMTAB    "SHT_SYMTAB"
  , (,) SHT_STRTAB    "SHT_STRTAB"
  , (,) SHT_RELA      "SHT_RELA"
  , (,) SHT_HASH      "SHT_HASH"
  , (,) SHT_DYNAMIC   "SHT_DYNAMIC"
  , (,) SHT_NOTE      "SHT_NOTE"
  , (,) SHT_NOBITS    "SHT_NOBITS"
  , (,) SHT_REL       "SHT_REL"
  , (,) SHT_SHLIB     "SHT_SHLIB"
  , (,) SHT_DYNSYM    "SHT_DYNSYM"
  , (,) SHT_INIT_ARRAY    "SHT_INIT_ARRAY"
  , (,) SHT_FINI_ARRAY    "SHT_FINI_ARRAY"
  , (,) SHT_PREINIT_ARRAY "SHT_PREINIT_ARRAY"
  , (,) SHT_GROUP         "SHT_GROUP"
  , (,) SHT_SYMTAB_SHNDX  "SHT_SYMTAB_SHNDX"
  , (,) SHT_LOOS          "SHT_LOOS"
  , (,) SHT_ANDROID_REL   "SHT_ANDROID_REL"
  , (,) SHT_ANDROID_RELA  "SHT_ANDROID_RELA"
  , (,) SHT_GNU_ATTRIBUTES "SHT_GNU_ATTRIBUTES"
  , (,) SHT_GNU_HASH       "SHT_GNU_HASH"
  , (,) SHT_GNU_verdef     "SHT_GNU_verdef"
  , (,) SHT_GNU_verneed    "SHT_GNU_verneed"
  , (,) SHT_GNU_versym     "SHT_GNU_versym"
  , (,) SHT_HIOS           "SHT_HIOS"
  , (,) SHT_LOPROC         "SHT_LOPROC"
  , (,) SHT_ARM_EXIDX          "SHT_ARM_EXIDX"
  , (,) SHT_ARM_PREEMPTMAP     "SHT_ARM_PREEMPTMAP"
  , (,) SHT_ARM_ATTRIBUTES     "SHT_ARM_ATTRIBUTES"
  , (,) SHT_ARM_DEBUGOVERLAY   "SHT_ARM_DEBUGOVERLAY"
  , (,) SHT_ARM_OVERLAYSECTION "SHT_ARM_OVERLAYSECTION"
  ]

instance Show ElfSectionType where
  show tp =
    case Map.lookup tp sectionTagMap of
      Just nm -> nm
      Nothing | tp < SHT_LOOS -> show (fromElfSectionType tp)
              | otherwise -> showHex (fromElfSectionType tp) ""

------------------------------------------------------------------------
-- ElfSectionFlags

-- | Flags for sections
newtype ElfSectionFlags w = ElfSectionFlags { fromElfSectionFlags :: w }
  deriving (Eq, Bits)

instance (Bits w, Integral w, Show w) => Show (ElfSectionFlags w) where
  showsPrec d (ElfSectionFlags w) = showFlags "shf_none" names d w
    where names = V.fromList ["shf_write", "shf_alloc", "shf_execinstr", "8", "shf_merge", "shf_strings"]

-- | Empty set of flags
shf_none :: Num w => ElfSectionFlags w
shf_none = ElfSectionFlags 0x0

-- | Section contains writable data
shf_write :: Num w => ElfSectionFlags w
shf_write = ElfSectionFlags 0x1

-- | Section is allocated in memory image of program
shf_alloc :: Num w => ElfSectionFlags w
shf_alloc = ElfSectionFlags 0x2

-- | Section contains executable instructions
shf_execinstr :: Num w => ElfSectionFlags w
shf_execinstr = ElfSectionFlags 0x4

-- | The contents of this section can be merged with elements in
-- sections of the same name, type, and flags.
shf_merge :: Num w => ElfSectionFlags w
shf_merge = ElfSectionFlags 0x10

-- | Section contians null terminated strings.
shf_strings :: Num w => ElfSectionFlags w
shf_strings = ElfSectionFlags 0x20

-- | Section info contains section header index.
shf_info_link :: Num w => ElfSectionFlags w
shf_info_link = ElfSectionFlags 0x40

-- | Section info contains section index this applies.
shf_link_order :: Num w => ElfSectionFlags w
shf_link_order = ElfSectionFlags 0x80

-- | Non-standard OS specific handling required.
shf_os_nonconforming :: Num w => ElfSectionFlags w
shf_os_nonconforming = ElfSectionFlags 0x100

-- | Section is a member of a group.
shf_group :: Num w => ElfSectionFlags w
shf_group = ElfSectionFlags 0x200

-- | Section contains TLS data (".tdata" or ".tbss")
--
-- Information in it may be modified by the dynamic linker, but is only copied
-- once the binary is linked.
shf_tls :: Num w => ElfSectionFlags w
shf_tls = ElfSectionFlags 0x400

-- | Section contains compressed data.
shf_compressed :: Num w => ElfSectionFlags w
shf_compressed = ElfSectionFlags 0x800

------------------------------------------------------------------------
-- Shdr

-- | Byte alignment expected on start of section header table.
shdrTableAlign :: ElfClass w -> ElfWordType w
shdrTableAlign ELFCLASS32 = 4
shdrTableAlign ELFCLASS64 = 8

-- | A section header record with parameters for the name and word type.
--
-- The name parameter allows this type to support both bytestring and
-- offsets for names so library users do not necessarily have to
-- resolve section header names.
data Shdr nm w = Shdr
    { shdrName :: !nm
      -- ^ Offset of section in name table.
    , shdrType      :: !ElfSectionType
      -- ^ Type of the section.
    , shdrFlags     :: !(ElfSectionFlags w)
      -- ^ Attributes of the section.
    , shdrAddr      :: !w
      -- ^ The virtual address of the beginning of the section in memory.
      --
      -- This should be 0 for sections that are not loaded into target memory.
    , shdrOff       :: !(FileOffset w)
      -- ^ Offset of section in file.
    , shdrSize      :: !w
      -- ^ The size of the section.
    , shdrLink      :: !Word32
      -- ^ Contains a section index of an associated section, depending on section type.
    , shdrInfo      :: !Word32
      -- ^ Contains extra information for the index, depending on type.
    , shdrAddrAlign :: !w
      -- ^ Contains the required alignment of the section.
    , shdrEntSize   :: !w
      -- ^ Size of entries if section has a table.
    } deriving (Eq, Show)

-- | Return expected file size of shdr entry
shdrFileSize :: Num w => Shdr nm w -> w
shdrFileSize shdr =
  case shdrType shdr of
    SHT_NOBITS -> 0
    _ -> shdrSize shdr

-- | Range of bytes in the file used to store section data.
shdrFileRange :: Num w => Shdr nm w -> FileRange w
shdrFileRange shdr = (shdrOff shdr, shdrFileSize shdr)

------------------------------------------------------------------------
-- Special section headers

-- | Create initial secton header entry
initShdr :: Num w => nm -> Shdr nm w
initShdr nm =
  Shdr { shdrName = nm
            , shdrType = SHT_NULL
            , shdrFlags = shf_none
            , shdrAddr = 0
            , shdrOff  = 0
            , shdrSize = 0
            , shdrLink = 0
            , shdrInfo = 0
            , shdrAddrAlign = 0
            , shdrEntSize = 0
            }

------------------------------------------------------------------------
-- decodeShdr

getShdr32 :: ElfData -> Get (Shdr Word32 Word32)
getShdr32 d = do
  sh_name      <- getWord32 d
  sh_type      <- ElfSectionType  <$> getWord32 d

  sh_flags     <- ElfSectionFlags <$> getWord32 d
  sh_addr      <- getWord32 d
  sh_offset    <- getWord32 d
  sh_size      <- getWord32 d

  sh_link      <- getWord32 d
  sh_info      <- getWord32 d
  sh_addralign <- getWord32 d
  sh_entsize   <- getWord32 d
  pure $! Shdr { shdrName      = sh_name
                    , shdrType      = sh_type
                    , shdrFlags     = sh_flags
                    , shdrAddr      = sh_addr
                    , shdrOff       = FileOffset sh_offset
                    , shdrSize      = sh_size
                    , shdrLink      = sh_link
                    , shdrInfo      = sh_info
                    , shdrAddrAlign = sh_addralign
                    , shdrEntSize   = sh_entsize
                    }

getShdr64 :: ElfData -> Get (Shdr Word32 Word64)
getShdr64 d = do
  sh_name      <- getWord32 d
  sh_type      <- ElfSectionType  <$> getWord32 d
  sh_flags     <- ElfSectionFlags <$> getWord64 d
  sh_addr      <- getWord64 d
  sh_offset    <- getWord64 d
  sh_size      <- getWord64 d
  sh_link      <- getWord32 d
  sh_info      <- getWord32 d
  sh_addralign <- getWord64 d
  sh_entsize   <- getWord64 d
  pure $! Shdr { shdrName      = sh_name
                    , shdrType      = sh_type
                    , shdrFlags     = sh_flags
                    , shdrAddr      = sh_addr
                    , shdrOff       = FileOffset sh_offset
                    , shdrSize      = sh_size
                    , shdrLink      = sh_link
                    , shdrInfo      = sh_info
                    , shdrAddrAlign = sh_addralign
                    , shdrEntSize   = sh_entsize
                    }

getShdr :: ElfData -> ElfClass w -> Get (Shdr Word32 (ElfWordType w))
getShdr d ELFCLASS32 = getShdr32 d
getShdr d ELFCLASS64 = getShdr64 d

-- | Decode section header bytes
--
-- This assumes the bytestring contains a complete section header.
decodeShdr :: ElfData
           -> ElfClass w
           -> B.ByteString -- ^ Contents of section header
           -> Shdr Word32 (ElfWordType w)
decodeShdr d cl buf
  | B.length buf < fromIntegral (shdrEntrySize cl) = error $ "Buffer is too small."
  | otherwise =
    case strictRunGetOrFail (getShdr d cl) buf of
      Left _ -> error $ "internal: decodeShdr unexpected failure."
      Right (_,_,v) -> v

------------------------------------------------------------------------
-- encodeShdr

-- | Encode the section header into a builder.
encodeShdr :: ElfClass w -> ElfData -> Shdr Word32 (ElfWordType w) -> Bld.Builder
encodeShdr ELFCLASS32 d shdr
  =  putWord32 d (shdrName shdr)
  <> putWord32 d (fromElfSectionType (shdrType shdr))
  <> putWord32 d (fromElfSectionFlags (shdrFlags shdr))
  <> putWord32 d (shdrAddr shdr)
  <> putWord32 d (fromFileOffset (shdrOff shdr))
  <> putWord32 d (shdrSize shdr)
  <> putWord32 d (shdrLink shdr)
  <> putWord32 d (shdrInfo shdr)
  <> putWord32 d (shdrAddrAlign shdr)
  <> putWord32 d (shdrEntSize shdr)
encodeShdr ELFCLASS64 d shdr
  =  putWord32 d (shdrName shdr)
  <> putWord32 d (fromElfSectionType (shdrType shdr))
  <> putWord64 d (fromElfSectionFlags (shdrFlags shdr))
  <> putWord64 d (shdrAddr shdr)
  <> putWord64 d (fromFileOffset (shdrOff shdr))
  <> putWord64 d (shdrSize shdr)
  <> putWord32 d (shdrLink shdr)
  <> putWord32 d (shdrInfo shdr)
  <> putWord64 d (shdrAddrAlign shdr)
  <> putWord64 d (shdrEntSize shdr)

-- | Render the ELF section header table.
encodeShdrTable :: ElfClass w -> ElfData -> [Shdr Word32 (ElfWordType w)] -> Bld.Builder
encodeShdrTable cl d l = foldMap (encodeShdr cl d) l
