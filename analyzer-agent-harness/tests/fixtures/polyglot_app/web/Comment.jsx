import React from "react";

export default function Comment({ html, url }) {
  return (
    <div>
      <div dangerouslySetInnerHTML={{ __html: html }} />
      <a href={"javascript:" + url}>open</a>
    </div>
  );
}
