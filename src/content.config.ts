import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

const blogCollection = defineCollection({
  loader: glob({
    pattern: '**/*.md',
    base: './src/content/blog',
  }),

  schema: z.object({

    title: z.string(),

    description: z.string(),

    /**
     * The actual publication date.
     *
     * The Python generator sets this automatically.
     */
    date: z.coerce.date(),

    /**
     * Optional date for future manual updates.
     */
    updatedDate: z.coerce.date().optional(),

    /**
     * Article difficulty.
     */
    difficulty: z
      .enum([
        'Beginner',
        'Intermediate',
        'Advanced',
        'Expert',
      ])
      .default('Beginner'),

    /**
     * Author name.
     */
    author: z
      .string()
      .default('Abdul Muqeet Tabraiz'),

    /**
     * Article tags.
     */
    tags: z
      .array(z.string())
      .default([]),

    /**
     * Main article category.
     */
    category: z
      .string()
      .default('General'),

    /**
     * Hero image path.
     */
    image: z
      .string()
      .optional(),

    /**
     * Draft flag.
     */
    draft: z
      .boolean()
      .default(false),
  }),
});

export const collections = {
  blog: blogCollection,
};
