import os
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_text_splitters import (
    MarkdownHeaderTextSplitter,
    RecursiveCharacterTextSplitter,
)
from utils.vectors import storage_manager
from agents.base import init_embedding_model

# =========================
# CONFIG
# =========================

HACKTRICKS_PATH = "./hacktricks/src"
COLLECTION_NAME = "tools_documentation"
PERSIST_DIR = "./store/vector_db"

SKIP_FILES = ["README.md", "SUMMARY.md"]

# Chunking parameters
# 1000 chars ≈ 250 tokens — good granularity for dense technical HackTricks content.
# Overlap of 150 preserves context across chunk boundaries (e.g. code blocks split mid-command).
CHUNK_SIZE = 1000
CHUNK_OVERLAP = 150
MIN_CHUNK_SIZE = 100  # discard chunks shorter than this (pure headers, empty sections)

# =========================
# LOAD FILES
# =========================


def load_markdown_files(path: str):
    loader = DirectoryLoader(
        path,
        glob="**/*.md",
        loader_cls=TextLoader,
        show_progress=True,
    )
    docs = loader.load()
    print(f"[INFO] Loaded {len(docs)} raw markdown files")
    return docs


# =========================
# CHUNKING — Two-pass strategy
#
# WHY TWO PASSES:
#   MarkdownHeaderTextSplitter alone produces empty chunks whenever a HackTricks
#   section contains only nested headers with no body text (very common in index
#   pages and SUMMARY.md). This was the root cause of "no results" in the RAG.
#
# Pass 1 — MarkdownHeaderTextSplitter (strip_headers=False)
#   → Splits on H1/H2/H3 boundaries.
#   → Attaches h1/h2/h3 as metadata on every chunk.
#   → strip_headers=False keeps the header text inside the chunk body,
#     so the LLM sees the section title as context.
#
# Pass 2 — RecursiveCharacterTextSplitter
#   → Further splits large sections into CHUNK_SIZE pieces so no single
#     chunk overflows the embedding model's token limit.
#   → Preserves CHUNK_OVERLAP chars between adjacent chunks.
# =========================


def split_markdown(docs: list) -> list:
    header_splitter = MarkdownHeaderTextSplitter(
        headers_to_split_on=[
            ("#", "h1"),
            ("##", "h2"),
            ("###", "h3"),
        ],
        strip_headers=False,
    )

    char_splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
        separators=["\n\n", "\n", " ", ""],
    )

    split_docs = []
    skipped = 0

    for doc in docs:
        source = doc.metadata.get("source", "")

        if any(skip in source for skip in SKIP_FILES):
            continue

        # Pass 1: structural split
        header_chunks = header_splitter.split_text(doc.page_content)

        for hchunk in header_chunks:
            section_meta = {
                "source": source,
                "h1": hchunk.metadata.get("h1", ""),
                "h2": hchunk.metadata.get("h2", ""),
                "h3": hchunk.metadata.get("h3", ""),
            }

            body = hchunk.page_content.strip()
            if not body or len(body) < MIN_CHUNK_SIZE:
                skipped += 1
                continue

            # Pass 2: size-bounded split
            sub_chunks = char_splitter.create_documents(
                texts=[body],
                metadatas=[section_meta],
            )

            for sc in sub_chunks:
                if sc.page_content and len(sc.page_content.strip()) >= MIN_CHUNK_SIZE:
                    split_docs.append(sc)
                else:
                    skipped += 1

    print(f"[INFO] Generated {len(split_docs)} chunks ({skipped} skipped as too short)")
    return split_docs


# =========================
# BATCH EMBEDDING
# =========================


def embed_in_batches(store: storage_manager, documents: list, batch_size: int = 500):
    store.embed_documents(documents, batch_size=batch_size)


# =========================
# MAIN BUILD PIPELINE
# =========================


def main():
    print("[INFO] Removing existing vector DB if exists...")
    os.system(f"rm -rf {PERSIST_DIR}")

    print("[INFO] Loading embedding model...")
    embedding_model = init_embedding_model().get_model()

    store = storage_manager(
        collection_name=COLLECTION_NAME,
        persist_directory=PERSIST_DIR,
        embedding_function=embedding_model,
    )

    print("[INFO] Loading HackTricks markdown files...")
    raw_docs = load_markdown_files(HACKTRICKS_PATH)

    print("[INFO] Splitting with two-pass chunker (MarkdownHeader + RecursiveChar)...")
    split_docs = split_markdown(raw_docs)

    print("[INFO] Embedding into Chroma DB...")
    embed_in_batches(store, split_docs, batch_size=500)

    print("\n======================================================================")
    print("✅ HACKTRICKS RAG BUILD COMPLETE")
    print("======================================================================")
    print(f"Collection : {COLLECTION_NAME}")
    print(f"Chunks     : {len(split_docs)}")
    print(f"Path       : {PERSIST_DIR}")
    print("======================================================================")


if __name__ == "__main__":
    main()
