export interface Embedder {
	embed(text: string): Promise<Float32Array>;
	readonly dimensions: number;
	readonly model: string;
}

export class LocalEmbedder implements Embedder {
	readonly dimensions = 384;
	readonly model = "Xenova/bge-small-en-v1.5";
	private pipe:
		| ((
				text: string,
				options: { pooling: string; normalize: boolean },
		  ) => Promise<{ data: Float32Array }>)
		| null = null;

	private constructor() {}

	static async create(): Promise<LocalEmbedder> {
		const embedder = new LocalEmbedder();
		const { pipeline } = await import("@huggingface/transformers");
		embedder.pipe = (await pipeline("feature-extraction", "Xenova/bge-small-en-v1.5", {
			dtype: "fp32",
		})) as unknown as (
			text: string,
			options: { pooling: string; normalize: boolean },
		) => Promise<{ data: Float32Array }>;
		return embedder;
	}

	async embed(text: string): Promise<Float32Array> {
		if (!this.pipe) {
			throw new Error("Embedder not initialized");
		}
		const result = await this.pipe(text, {
			pooling: "mean",
			normalize: true,
		});
		return new Float32Array(result.data);
	}
}
