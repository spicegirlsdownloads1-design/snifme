/* Header parsing of image responses ALREADY received in DevTools (never fetches). */
(function(root){
  'use strict';
  const ascii=(b,pos,len)=>String.fromCharCode(...b.subarray(pos,pos+len));
  const be16=(b,o)=>b[o]*256+b[o+1];
  const be32=(b,o)=>((b[o]*16777216)+(b[o+1]<<16)+(b[o+2]<<8)+b[o+3])>>>0;
  const le16=(b,o)=>b[o]+(b[o+1]<<8);
  const le24=(b,o)=>b[o]+(b[o+1]<<8)+(b[o+2]<<16);
  const le32=(b,o)=>(b[o]+(b[o+1]<<8)+(b[o+2]<<16)+(b[o+3]*16777216))>>>0;
  function dimensions(b){
    if(!(b instanceof Uint8Array)||b.length<20) return {format:'unknown',width:null,height:null};
    let format='unknown',width=null,height=null;
    if(ascii(b,1,3)==='PNG'&&b[0]===137&&b.length>=24&&ascii(b,12,4)==='IHDR'){
      format='PNG';width=be32(b,16);height=be32(b,20);
    }else if(ascii(b,0,3)==='GIF'&&b.length>=10){
      format='GIF';width=le16(b,6);height=le16(b,8);
    }else if(ascii(b,0,2)==='BM'&&b.length>=26){
      format='BMP';width=le32(b,18);height=Math.abs(le32(b,22)|0);
    }else if(b[0]===255&&b[1]===216){
      format='JPEG';let i=2;
      while(i+3<b.length){
        if(b[i]!==255){i++;continue;}
        while(i<b.length&&b[i]===255)i++;
        const marker=b[i++];
        if(marker===0xDA||marker===0xD9)break;
        if(marker===0xD8||marker===0x01||(marker>=0xD0&&marker<=0xD7))continue;
        if(i+2>b.length)break;
        const len=be16(b,i);
        if(len<2||i+len>b.length)break;
        if([0xC0,0xC1,0xC2,0xC3,0xC5,0xC6,0xC7,0xC9,0xCA,0xCB,0xCD,0xCE,0xCF].includes(marker)&&len>=7){
          height=be16(b,i+3);width=be16(b,i+5);break;
        }
        i+=len;
      }
    }else if(ascii(b,0,4)==='RIFF'&&ascii(b,8,4)==='WEBP'&&b.length>=30){
      format='WebP';const variant=ascii(b,12,4);
      if(variant==='VP8X'){width=1+le24(b,24);height=1+le24(b,27);}
      else if(variant==='VP8L'&&b[20]===0x2f){width=1+(((b[22]&0x3f)<<8)|b[21]);height=1+(((b[24]&0x0f)<<10)|(b[23]<<2)|((b[22]&0xc0)>>6));}
      else if(variant==='VP8 '&&b.length>=30&&b[23]===0x9d&&b[24]===0x01&&b[25]===0x2a){width=le16(b,26)&0x3fff;height=le16(b,28)&0x3fff;}
    }
    if(!Number.isSafeInteger(width)||!Number.isSafeInteger(height)||width<1||height<1||width>100000||height>100000){width=null;height=null;}
    return {format,width,height};
  }
  root.THIHeader={dimensions};
})(globalThis);
