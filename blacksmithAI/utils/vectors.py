from langchain_chroma import Chroma
from rich import print
import logging

logger = logging.getLogger("vectors")


class storage_manager:

    def __init__(
        self,
        collection_name: str = "example",
        persist_directory: str = "vector_db",
        embedding_function=None,
    ):
        self.persist_directory = persist_directory
        self.collection_name = collection_name
        self.embedding = embedding_function

        self.client = Chroma(
            collection_name=self.collection_name,
            persist_directory=self.persist_directory,
            embedding_function=self.embedding,
        )

    def get_client(self):
        return self.client

    def embed_documents(self, documents, batch_size: int = 500):
        """Embed documents into the vector store in batches."""
        total = len(documents)
        inserted = 0

        for i in range(0, total, batch_size):
            batch = documents[i : i + batch_size]

            # Discard empty or near-empty chunks (critical for HackTricks cleanup)
            batch = [
                d
                for d in batch
                if d.page_content and len(d.page_content.strip()) > 50
            ]

            if not batch:
                logger.warning(f"[SKIP] batch {i} — all docs empty after filtering")
                continue

            self.client.add_documents(documents=batch)
            inserted += len(batch)
            print(f"[INFO] batch {i}-{i + len(batch)} inserted ({inserted}/{total})")

        print(f"[DONE] {inserted} documents embedded (out of {total})")

    def query(
        self,
        query_text: str,
        n_results: int = 8,
        filter: dict = None,
        score_threshold: float = 0.35,
    ) -> list:
        """
        Retrieve documents with score filtering.

        Uses similarity_search_with_relevance_scores so each result comes with
        a relevance score in [0, 1]. Results below score_threshold are discarded
        before being sent to the LLM — this was the main reason the LLM was
        reporting "no results found" despite documents existing in the store.

        Args:
            query_text      : Natural language query.
            n_results       : Max number of results to return after filtering.
            filter          : Optional Chroma metadata filter dict.
            score_threshold : Minimum relevance score to keep (default 0.35).

        Returns:
            List of (Document, float) tuples sorted by descending score.
        """
        kwargs = {"k": n_results * 2}  # fetch more, then trim by score
        if filter:
            kwargs["filter"] = filter

        try:
            results_with_scores = self.client.similarity_search_with_relevance_scores(
                query_text, **kwargs
            )
        except Exception as e:
            logger.error(f"[RAG] query failed: {e}")
            return []

        # Filter and sort
        filtered = [
            (doc, score)
            for doc, score in results_with_scores
            if score >= score_threshold
        ]
        filtered.sort(key=lambda x: x[1], reverse=True)
        top = filtered[:n_results]

        logger.debug(
            f"[RAG] '{query_text}' → {len(results_with_scores)} raw, "
            f"{len(filtered)} above threshold={score_threshold}, "
            f"{len(top)} returned"
        )

        return top
