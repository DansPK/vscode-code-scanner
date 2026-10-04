import React from "react";

export function Profile(props: { bio: string }) {
  return <div dangerouslySetInnerHTML={{ __html: props.bio }} />;
}
