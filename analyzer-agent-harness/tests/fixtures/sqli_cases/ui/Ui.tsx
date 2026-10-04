export function Ui({ fontClass, index, n }: { fontClass: string; index: number; n: number }) {
  return (
    <div className={`flex flex-col gap-1.5 w-full relative ${fontClass}`} key={`ellipsis-${index}`}>
      {`Select ${n} items from the list`}
      {"Order by " + fontClass}
    </div>
  );
}
