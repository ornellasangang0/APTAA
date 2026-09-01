from langchain_openai import ChatOpenAI
from langchain_openai.embeddings import OpenAIEmbeddings
from dotenv import load_dotenv
import os
import json
from openai import RateLimitError

load_dotenv()

#load configuration
config = json.load(open("./config.json", "r"))

# select provider and model
default_provider = config['defaults']['provider']

base_url = config['provider'][f'{default_provider}']['base_url'] or 'https://openrouter.ai/api/v1' # default openrouter
default_model = config['provider'][f'{default_provider}']['default_model'] or "mistralai/devstral-2512"
context_size = config['provider'][f'{default_provider}']['default_model_config']['context_size'] or 200000
max_retries = config['provider'][f'{default_provider}']['default_model_config']['max_retries'] or 3
stream_usage = config['provider'][f'{default_provider}']['default_model_config']['stream_usage'] or True
max_tokens = config['provider'][f'{default_provider}']['default_model_config']['max_tokens'] or None
embedding_model = config['provider'][f'{default_provider}']['default_embedding_model'] or "openai/text-embedding-3-small"

# Context limit configuration
safety_margin_percent = config['provider'][f'{default_provider}']['default_model_config'].get('safety_margin_percent', 30)
max_result_chars = config['provider'][f'{default_provider}']['default_model_config'].get('max_result_chars', None)

# Retry strategy configuration
retry_config = config.get('retry_config', {})
orchestrator_max_retries = retry_config.get('orchestrator_max_retries', 1)
subagent_max_retries = retry_config.get('subagent_max_retries', 1)
model_max_retries = retry_config.get('model_max_retries', 1)

# api key
key = f'{default_provider.upper()}_API_KEY'
api_key = os.getenv(key, "") # get key from env


def get_context_limits() -> tuple[int, float, int]:
    """
    Get context limit configuration for the current LLM provider.
    
    Returns:
        Tuple of (context_size, safety_margin_percent, max_result_chars)
    """
    return context_size, safety_margin_percent, max_result_chars


def get_retry_config() -> tuple[int, int, int]:
    """
    Get retry configuration for agents and models.
    
    Returns:
        Tuple of (orchestrator_max_retries, subagent_max_retries, model_max_retries)
    """
    return orchestrator_max_retries, subagent_max_retries, model_max_retries


class init_model:
    def __init__(self, reasoning_effort=None, temperature=0):
        # Use configured max_retries instead of hardcoded value
        effective_max_retries = model_max_retries if model_max_retries is not None else 1
        
        # Disable internal retries to avoid conflicts, use with_retry instead
        self.model = ChatOpenAI(
            model=default_model,
            api_key=api_key,
            base_url=base_url,
            max_retries=effective_max_retries,
            stream_usage=stream_usage,
            profile={"max_input_tokens": context_size},
            reasoning_effort=reasoning_effort,
            temperature=temperature,
            max_completion_tokens=max_tokens
        )

    def get_model(self):
        return self.model
    
class init_embedding_model():
    
    def __init__(self):

        self.model = OpenAIEmbeddings(
            model=embedding_model,
            api_key=api_key,
            base_url=base_url,
            max_retries=model_max_retries if model_max_retries is not None else 3,
        )

    def get_model(self):
        return self.model
    
    
