export interface ResolverMap {
    [key: string]: {
      [key: string]: (...args: any[]) => any;
    };
  }
  