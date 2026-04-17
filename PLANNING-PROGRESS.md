# 📊 Attack Planning Progress Indicators

## What You'll See Now:

### Before (No Visibility):

```
Planning attacks with LLM... this may take a while.
[LONG WAIT - NO FEEDBACK]
```

### After (Full Visibility):

```
Planning attacks with LLM... this may take a while.
  📋 Planning attacks for 6 categories...
    [1/6] prompt_injection...
      🤖 Calling LLM (z-ai/glm-5.1)...
      ✅ LLM responded (2340ms)
    5 attacks (2450ms)
    [2/6] output_evasion...
      🤖 Calling LLM (z-ai/glm-5.1)...
      ✅ LLM responded (1890ms)
    4 attacks (1920ms)
    [3/6] content_filter_bypass...
      🤖 Calling LLM (z-ai/glm-5.1)...
      ✅ LLM responded (3200ms)
    6 attacks (3250ms)
    ...
  ✍️ Rewriting 15 seed payloads for realism...
    📝 Rewriting batch 1/2 (10 attacks)...
    📝 Rewriting batch 2/2 (5 attacks)...
  ✅ Seed rewriting completed (1200ms)
```

## Progress Breakdown:

### 1. **Category Planning** `[1/6] prompt_injection...`

- Shows which attack category is being planned
- Progress through total categories
- Time taken per category

### 2. **LLM Calls** `🤖 Calling LLM (z-ai/glm-5.1)...`

- When LLM generation starts
- Which model is being used
- Response time for each call

### 3. **Attack Generation** `5 attacks (2450ms)`

- Number of attacks generated per category
- Total time including LLM call

### 4. **Seed Rewriting** `✍️ Rewriting 15 seed payloads...`

- Making predefined attacks sound more realistic
- Batch processing progress
- Total rewriting time

### 5. **Refinement** `🔄 Refining 3 partial results...` (Round 2+)

- Improving attacks that partially succeeded
- Number of refined attacks generated

## Why Planning Takes Time:

**Your Config Analysis:**

- **6 attack categories** enabled
- **3 attacks per category** = 18 total attacks
- **8 strategies per round** = complex generation
- **OpenRouter z-ai/glm-5.1** = can be slower than other providers

**Time Breakdown (Typical):**

- **LLM generation:** 1-5 seconds per category
- **Seed rewriting:** 1-3 seconds per batch
- **Total planning:** 10-30 seconds for 6 categories

## Speed Optimization Tips:

### **Quick Testing:**

```json
{
  "attackConfig": {
    "enabledCategories": ["prompt_injection", "content_filter_bypass"],
    "maxAttacksPerCategory": 2,
    "strategiesPerRound": 3
  }
}
```

### **Faster Model:**

```json
{
  "llmProvider": "anthropic",
  "llmModel": "claude-haiku-4-5-20251001"
}
```

### **Disable Rewriting:**

```json
{
  "enableLlmGeneration": false // Uses only predefined attacks
}
```

## Now You Can Track Progress! 📈

No more mystery waiting - you'll see exactly:

- ✅ Which category is being processed
- ✅ How long each LLM call takes
- ✅ Progress through the planning pipeline
- ✅ Total time breakdown

**Much better visibility into what's happening!** 🎯
