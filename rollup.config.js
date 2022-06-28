import typescript from 'rollup-plugin-typescript';
import commonjs from 'rollup-plugin-commonjs'
import dts from "rollup-plugin-dts";
import copy from 'rollup-plugin-copy';

export default [{
  name: 'apipostSampleModule',
  input: 'src/index.ts',
  output: {
    name: 'apipostSampleModule',
    file: 'dist/index.js',
    format: 'cjs'
  },
  plugins: [
    typescript(),
    commonjs(),
    copy({
      targets: [
        { src: 'src/apiSchema.json', dest: 'dist/' },
      ]
    })
  ]
},
{
  input: "src/index.ts",
  output: [{ file: "dist/index.d.ts", format: "es" }],
  plugins: [dts()],
}]

