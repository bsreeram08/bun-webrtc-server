export type Reverser<T extends Record<PropertyKey, PropertyKey>> = {
    [P in keyof T as T[P]]: P;
};

export type Split<S extends string> = string extends S
    ? string[]
    : S extends ''
      ? []
      : S extends `${infer T}${''}${infer U}`
        ? [T, ...Split<U>]
        : [S];

export type Prettify<T> = {
    [K in keyof T]: T[K];
    // eslint-disable-next-line @typescript-eslint/ban-types
} & {};

export type RemoveNever<T> = Omit<T, PickNeverKeys<T, keyof T>[number]>;

export type PickNeverKeys<T, K> = [K extends keyof T ? (T[K] extends never ? K : '') : K];

export type KeyOf<T> = Extract<keyof T, string>;
export type Writeable<T extends { [x: string]: unknown }, K extends string> = {
    [P in K]: T[P];
};

export type TValidatorResponse<V> =
    | {
          status: 'ERROR';
          error: string;
      }
    | { status: 'SUCCESS'; data: V };

export type ValueOf<T> = T[keyof T];

export type KeysOfUnion<T> = T extends T ? keyof T : never;

export type FilterKeys<Type, Key extends keyof Type> = {
    [S in Key]: Type[S];
};

export type RemoveKeysOfType<Type, Key> = {
    [key in keyof Type as Type[key] extends Key ? never : key]: Type[key];
};

export type UnionOfArrayValues<T extends Array<unknown>> = T[number];
